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
  critical: "#b00020",
  high: "#d9534f",
  medium: "#f0ad4e",
  low: "#5bc0de",
  info: "#777",
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
};

export function StatusPill({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function Card({ title, children, actions }:
  { title?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="panel">
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

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return <div className="state state-loading" role="status">{label}</div>;
}

export interface Loader<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  reload: () => void;
}

/** Fetch on mount (and on `deps` change), keeping the three states apart. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []): Loader<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    fn()
      .then((value) => { if (live) { setData(value); setError(null); } })
      .catch((e: Error) => { if (live) { setError(e); setData(null); } })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { data, error, loading, reload };
}

/** True for `[]` and for a paged `{rows: []}` — the two shapes the API client returns. */
function isEmpty(data: unknown): boolean {
  if (Array.isArray(data)) return data.length === 0;
  if (data && typeof data === "object" && Array.isArray((data as { rows?: unknown[] }).rows)) {
    return (data as { rows: unknown[] }).rows.length === 0;
  }
  return false;
}

/** Render a loader's three states. `children` only ever sees real, loaded data. */
export function Async<T>({ loader, children, empty }:
  { loader: Loader<T>; children: (data: T) => ReactNode; empty?: ReactNode }) {
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
                background: colors?.[s.key] ?? "#4a6fa5",
              }}
            />
          </span>
          <span className="bar-value">{s.value}</span>
        </div>
      ))}
    </div>
  );
}
