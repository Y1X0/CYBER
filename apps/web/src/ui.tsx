// Shared primitives.
//
// The important one is `Async`. Loading, failed and loaded are three different states, and the
// failure carries the server's own words. Collapsing failure into "nothing here" is the specific
// lie this product must never tell — a customer looking at an empty findings table has to be able
// to tell "you have no findings" from "we could not ask".

import { ReactNode, useCallback, useEffect, useState } from "react";
import { ApiError } from "./api";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export const SEV_COLOR: Record<string, string> = {
  critical: "#ff2d4f",
  high: "#e01b3c",
  medium: "#ff8a1a",
  low: "#62b8ff",
  info: "#5f687d",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className="badge" style={{ background: SEV_COLOR[severity] ?? "#777" }}>
      {severity}
    </span>
  );
}

/** Scan and engine states, with the wording that keeps "did not run" apart from "clean". */
export const SCAN_STATE: Record<string, { label: string; tone: string; meaning: string }> = {
  queued: { label: "Queued", tone: "wait", meaning: "Accepted and waiting for a scanner." },
  running: { label: "Running", tone: "wait", meaning: "A scanner is working on this now." },
  completed: { label: "Completed", tone: "ok", meaning: "Every requested engine ran and reported." },
  partial: {
    label: "Partial", tone: "warn",
    meaning: "Some engines ran and some did not. What the missing engines would have found is " +
             "unknown — not absent.",
  },
  failed: {
    label: "Failed", tone: "bad",
    meaning: "This scan did not produce a result. Nothing here means your systems are clean.",
  },
};

export const ENGINE_STATE: Record<string, { label: string; tone: string }> = {
  checked: { label: "Checked", tone: "ok" },
  running: { label: "Running", tone: "wait" },
  queued: { label: "Queued", tone: "wait" },
  inconclusive: { label: "Inconclusive", tone: "warn" },
  not_checked: { label: "Not checked", tone: "bad" },
  blocked: { label: "Blocked — not authorized", tone: "bad" },
};

export function StatusPill({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function Card({ title, children, actions }:
  { title?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="panel hud-corners">
      {(title || actions) && (
        <div className="panel-head">
          {title && <h3>{title}</h3>}
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, tone, hint }:
  { label: string; value: ReactNode; tone?: string; hint?: string }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function EmptyState({ title, body, action }:
  { title: string; body: ReactNode; action?: ReactNode }) {
  return (
    <div className="state state-empty" role="status">
      <h4>{title}</h4>
      <p>{body}</p>
      {action}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: Error; retry?: () => void }) {
  const status = error instanceof ApiError ? error.status : 0;
  return (
    <div className="state state-error" role="alert">
      <h4>This could not be loaded</h4>
      {/* The server's own words. A generic "something went wrong" hides the one fact that would
          let the customer act — or tell them their session simply expired. */}
      <p className="err">{error.message}</p>
      {status === 401 && <p>Your session may have expired. Sign in again.</p>}
      <p className="muted">
        Nothing on this screen should be read as a result. This is a failure to ask, not an answer.
      </p>
      {retry && <button onClick={retry}>Try again</button>}
    </div>
  );
}

export function Blocked({ title, body, children }:
  { title: string; body: ReactNode; children?: ReactNode }) {
  return (
    <div className="state state-blocked" role="status">
      <h4>{title}</h4>
      <p>{body}</p>
      {children}
    </div>
  );
}

export function Spinner({ label = "Querying" }: { label?: string }) {
  return <div className="state state-loading" role="status">{label}</div>;
}

/**
 * The control plane is a free-tier instance that sleeps when idle, and a request against a cold
 * instance is rejected before any HTTP status exists (the holding page Render serves while starting
 * carries no CORS headers). That is `ApiError(status: 0)` from the client. It reads identically to
 * "the server is gone", but it is not — it is "starting, try again in a moment". Naming it lets the
 * UI show a waking state and retry, instead of an error the customer cannot act on or, worse, a
 * stale scan status that looks stuck.
 */
export function isBackendWaking(error: Error | null): boolean {
  return error instanceof ApiError && error.status === 0;
}

export function WakingState({ retry }: { retry?: () => void }) {
  return (
    <div className="state state-loading" role="status" aria-live="polite">
      <h4>The backend is waking up…</h4>
      <p className="muted">
        The control plane sleeps when idle to stay on the free tier, so the first request after a
        quiet spell takes up to a minute while it starts. This is not a stuck scan — the status will
        refresh itself the moment the backend answers.
      </p>
      {retry && <button onClick={retry}>Retry now</button>}
    </div>
  );
}

export interface Loader<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  // True while the last attempt failed because the backend was unreachable (a sleeping free-tier
  // instance) and we are auto-retrying. It is not an error state: a cold start recovers on its own.
  waking: boolean;
  reload: () => void;
}

// A cold start on Render's free plan takes ~30–50s; auto-retry with a short backoff spans that
// window, then falls through to a real error if the backend truly is not answering.
const _WAKE_RETRIES = 8;

/** Fetch on mount (and on `deps` change), keeping the states apart and riding out a cold start. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []): Loader<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [waking, setWaking] = useState(false);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    setLoading(true);
    setError(null);
    setWaking(false);

    const run = () => {
      fn()
        .then((value) => {
          if (!live) return;
          setData(value); setError(null); setWaking(false); setLoading(false);
        })
        .catch((e: Error) => {
          if (!live) return;
          // A sleeping instance is a transient state, not a failure — ride it out.
          if (isBackendWaking(e) && attempt < _WAKE_RETRIES) {
            attempt += 1;
            setWaking(true);
            setLoading(false);
            timer = setTimeout(run, Math.min(2000 * attempt, 8000));
            return;
          }
          setError(e); setData(null); setWaking(false); setLoading(false);
        });
    };
    run();

    return () => { live = false; if (timer) clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { data, error, loading, waking, reload };
}

/** True for `[]` and for a paged `{rows: []}` — the two shapes the API client returns. */
function isEmpty(data: unknown): boolean {
  if (Array.isArray(data)) return data.length === 0;
  if (data && typeof data === "object" && Array.isArray((data as { rows?: unknown[] }).rows)) {
    return (data as { rows: unknown[] }).rows.length === 0;
  }
  return false;
}

/** Render a loader's states. `children` only ever sees real, loaded data. */
export function Async<T>({ loader, children, empty }:
  { loader: Loader<T>; children: (data: T) => ReactNode; empty?: ReactNode }) {
  // A sleeping backend on first load is a waking state, not an error and not an empty result.
  if (loader.waking && loader.data === null) return <WakingState retry={loader.reload} />;
  if (loader.loading && loader.data === null) return <Spinner />;
  if (loader.error) return <ErrorState error={loader.error} retry={loader.reload} />;
  if (loader.data === null) return <Spinner />;
  if (empty && isEmpty(loader.data)) return <>{empty}</>;
  return <>{children(loader.data)}</>;
}

export function when(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

export function ago(seconds: number): string {
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

/** A minimal bar chart over real values. No axes it cannot justify, no interpolation. */
export function Bars({ series, colors }:
  { series: { key: string; value: number }[]; colors?: Record<string, string> }) {
  const max = Math.max(1, ...series.map((s) => s.value));
  return (
    <div className="bars">
      {series.map((s) => (
        <div className="bar-row" key={s.key}>
          <span className="bar-key">{s.key}</span>
          <span className="bar-track">
            <span
              className="bar-fill"
              style={{
                width: `${(s.value / max) * 100}%`,
                background: colors?.[s.key] ?? "var(--crimson-dim)",
              }}
            />
          </span>
          <span className="bar-value">{s.value}</span>
        </div>
      ))}
    </div>
  );
}

// The assessment flow, shown as a step strip. Steps are LINKS (never buttons) so they never collide
// with the navigation's button labels. It orients a person in the journey the product actually runs:
// Asset → Scan → Findings → Risk → Components → SBOM → Report → Remediation.
const JOURNEY_STEPS: { key: string; label: string; to: string | null }[] = [
  { key: "asset", label: "Asset", to: "assets" },
  { key: "scan", label: "Scan", to: null },
  { key: "findings", label: "Findings", to: "findings" },
  { key: "risk", label: "Risk", to: "findings" },
  { key: "components", label: "Components", to: "components" },
  { key: "sbom", label: "SBOM", to: "components" },
  { key: "report", label: "Report", to: "reports" },
  { key: "remediation", label: "Remediation", to: "remediation" },
];

export function JourneyStrip({ active, scanId }: { active: string; scanId?: string }) {
  const activeIdx = JOURNEY_STEPS.findIndex((s) => s.key === active);
  return (
    <nav className="journey" aria-label="Assessment flow">
      {JOURNEY_STEPS.map((s, i) => {
        const state = i < activeIdx ? "done" : i === activeIdx ? "on" : "next";
        const href = s.to ? `#/${s.to}` : (scanId ? `#/scans/${scanId}` : undefined);
        const cls = `journey-step ${state}`;
        const inner = <><span className="journey-dot" aria-hidden="true" />{s.label}</>;
        return href
          ? <a key={s.key} className={cls} href={href}
               aria-current={state === "on" ? "step" : undefined}>{inner}</a>
          : <span key={s.key} className={cls}>{inner}</span>;
      })}
    </nav>
  );
}
