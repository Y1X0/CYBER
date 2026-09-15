// Motion and atmosphere components.
//
// No animation library. Framer Motion would add ~110KB to a bundle that a customer downloads
// before they can look at their own security posture, and every effect below is transform,
// opacity or a canvas — the three things browsers already do on the compositor. A security
// product also has a specific reason to keep its dependency list short: every package here is
// supply chain the customer inherits.
//
// Three rules hold across this file:
//   1. Nothing animates that does not report state, give feedback, or build the atmosphere the
//      brief asks for. Decoration that says nothing gets deleted, not tuned down.
//   2. Every rAF loop checks `prefers-reduced-motion` and does not start. Hiding an animation
//      still pays for it.
//   3. Canvas work scales with --fx-density, which collapses to 0 on touch and on reduced
//      motion, so phones run the same components with the heavy parts absent.

import {
  ReactNode, useEffect, useMemo, useRef, useState,
} from "react";

/** Read a CSS variable as a number. Effects take their budget from the stylesheet, not from a
 *  duplicate breakpoint list that will drift from it. */
function cssNumber(name: string, fallback: number): number {
  if (typeof window === "undefined") return fallback;
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const n = Number.parseFloat(raw);
  return Number.isFinite(n) ? n : fallback;
}

export function prefersReducedMotion(): boolean {
  return typeof window !== "undefined"
    && typeof window.matchMedia === "function"
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/* ══ particle field ═══════════════════════════════════════════════════════════════════════════
 * Drifting embers with occasional link lines — a network settling, not snow. Canvas rather than
 * DOM nodes: 60 elements each with their own transform is 60 composited layers, one canvas is
 * one.
 */
export function ParticleField() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    // Two gates, because they fail in different situations. The media query is authoritative and
    // works before any stylesheet has applied; the CSS variable carries the finer per-device
    // budget. Reading only the variable would start a full particle field in any environment
    // where the stylesheet has not loaded yet.
    if (prefersReducedMotion()) return;
    const density = cssNumber("--fx-density", 1);
    if (density <= 0) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Cap the backing store at 1.5x. Retina phones report 3x, and a 3x full-screen canvas is
    // nine times the fill rate for a difference nobody can see on drifting 1px dots.
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    let w = 0, h = 0;

    type P = { x: number; y: number; vx: number; vy: number; r: number; a: number; ember: boolean };
    let parts: P[] = [];

    function resize() {
      if (!canvas || !ctx) return;
      w = canvas.clientWidth; h = canvas.clientHeight;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.round(Math.min(74, (w * h) / 17000) * density);
      parts = Array.from({ length: count }, () => ({
        x: Math.random() * w, y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.14,
        vy: -0.05 - Math.random() * 0.16,            // embers rise
        r: 0.5 + Math.random() * 1.3,
        a: 0.12 + Math.random() * 0.4,
        ember: Math.random() < 0.22,
      }));
    }

    let raf = 0;
    function frame() {
      if (!ctx) return;
      ctx.clearRect(0, 0, w, h);

      for (const p of parts) {
        p.x += p.vx; p.y += p.vy;
        if (p.y < -10) { p.y = h + 10; p.x = Math.random() * w; }
        if (p.x < -10) p.x = w + 10;
        if (p.x > w + 10) p.x = -10;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = p.ember
          ? `rgba(255, 122, 40, ${p.a})`
          : `rgba(255, 90, 114, ${p.a * 0.75})`;
        ctx.fill();
      }

      // Link lines between near neighbours: the "network" read. O(n²) is fine at n≤74 and the
      // loop is skipped entirely on phones, where the count is a third of that anyway.
      if (density >= 0.9) {
        for (let i = 0; i < parts.length; i++) {
          for (let j = i + 1; j < parts.length; j++) {
            const dx = parts[i].x - parts[j].x, dy = parts[i].y - parts[j].y;
            const d2 = dx * dx + dy * dy;
            if (d2 < 15000) {
              ctx.beginPath();
              ctx.moveTo(parts[i].x, parts[i].y);
              ctx.lineTo(parts[j].x, parts[j].y);
              ctx.strokeStyle = `rgba(224, 27, 60, ${0.05 * (1 - d2 / 15000)})`;
              ctx.lineWidth = 0.5;
              ctx.stroke();
            }
          }
        }
      }
      raf = requestAnimationFrame(frame);
    }

    resize();
    frame();
    window.addEventListener("resize", resize);

    // A tab nobody is looking at gets no frames. Battery is a feature on a phone.
    const onVisibility = () => {
      if (document.hidden) { cancelAnimationFrame(raf); raf = 0; }
      else if (!raf) raf = requestAnimationFrame(frame);
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return <canvas ref={ref} className="bg-particles"
                 style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }} />;
}

/** The seven background layers, in one place so no screen re-creates its own atmosphere. */
export function Backdrop() {
  return (
    <div className="bg-stack" aria-hidden="true">
      <div className="bg-fog" />
      <div className="bg-grid" />
      <div className="bg-eclipse" />
      <ParticleField />
      <div className="bg-sweep" />
      <div className="bg-scanlines" />
    </div>
  );
}

/* ══ boot sequence ════════════════════════════════════════════════════════════════════════════
 * Shown once per session, and short. A loading screen that adds real waiting to a working app is
 * a cost paid by the operator every day for an effect they stop noticing on day two, so this runs
 * ~1.4s, is skippable with any key or click, and never gates the first paint of real data —
 * the app mounts behind it.
 */
const BOOT_MODULES = [
  "KERNEL", "NETWORK", "SCANNER", "THREAT ENGINE", "POLICY", "DATABASE",
];

export function BootSequence({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState(0);
  const [leaving, setLeaving] = useState(false);
  const reduced = useMemo(prefersReducedMotion, []);

  useEffect(() => {
    if (reduced) { onDone(); return; }
    let cancelled = false;
    const timers: number[] = [];
    BOOT_MODULES.forEach((_, i) => {
      timers.push(window.setTimeout(() => { if (!cancelled) setStep(i + 1); }, 120 + i * 150));
    });
    timers.push(window.setTimeout(() => { if (!cancelled) setLeaving(true); }, 120 + BOOT_MODULES.length * 150 + 260));
    timers.push(window.setTimeout(() => { if (!cancelled) onDone(); }, 120 + BOOT_MODULES.length * 150 + 820));
    return () => { cancelled = true; timers.forEach(clearTimeout); };
  }, [onDone, reduced]);

  // Skippable. An operator who has seen it forty times should be able to get past it.
  useEffect(() => {
    const skip = () => { setLeaving(true); window.setTimeout(onDone, 220); };
    window.addEventListener("keydown", skip, { once: true });
    window.addEventListener("pointerdown", skip, { once: true });
    return () => {
      window.removeEventListener("keydown", skip);
      window.removeEventListener("pointerdown", skip);
    };
  }, [onDone]);

  if (reduced) return null;

  return (
    <div className={`boot${leaving ? " done" : ""}`} role="status" aria-label="Starting">
      <div className="boot-inner">
        <div className="boot-title">Security Core</div>
        <div className="boot-sub">Initializing · encrypted channel</div>
        {BOOT_MODULES.map((m, i) => (
          i < step && (
            <div className="boot-row" key={m} style={{ animationDelay: `${i * 20}ms` }}>
              <span>{m}</span>
              <span className="ok">ONLINE</span>
            </div>
          )
        ))}
        <div className="boot-bar">
          <span style={{ width: `${(step / BOOT_MODULES.length) * 100}%` }} />
        </div>
        {step >= BOOT_MODULES.length && <div className="boot-grant">Access granted</div>}
      </div>
    </div>
  );
}

/* ══ route transition ═════════════════════════════════════════════════════════════════════════ */

/** A scan wipe on route change. Non-blocking: it is an overlay with pointer-events: none, so the
 *  new screen is interactive from its first frame. */
export function RouteTransition({ routeKey, children }:
  { routeKey: string; children: ReactNode }) {
  const [wipe, setWipe] = useState(0);
  const first = useRef(true);

  useEffect(() => {
    if (first.current) { first.current = false; return; }  // no wipe on initial mount
    setWipe((n) => n + 1);
  }, [routeKey]);

  return (
    <>
      {wipe > 0 && <div className="route-fx" key={wipe} aria-hidden="true" />}
      <div className="route-body" key={routeKey}>{children}</div>
    </>
  );
}

/* ══ animated counter ═════════════════════════════════════════════════════════════════════════ */

/**
 * Counts up to a real value.
 *
 * One text node, not two. A first attempt rendered the animated number plus a visually-hidden
 * copy of the true value, which put the same figure in the DOM twice — ambiguous for anything
 * querying by text, and a second place for the number to be wrong. Screen readers are not a live
 * region here: they read whatever is present when the user reaches it, which is the settled
 * value.
 */
export function Counter({ value, className }: { value: number; className?: string }) {
  const [shown, setShown] = useState(() => (prefersReducedMotion() ? value : 0));
  const prev = useRef(value);

  useEffect(() => {
    if (prefersReducedMotion()) { setShown(value); prev.current = value; return; }
    const from = prev.current;
    const to = value;
    prev.current = value;
    if (from === to) { setShown(to); return; }

    const duration = Math.min(760, 220 + Math.abs(to - from) * 26);
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);               // ease-out cubic
      setShown(Math.round(from + (to - from) * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);

  return <span className={className}>{shown}</span>;
}

/* ══ security gauge ═══════════════════════════════════════════════════════════════════════════ */

/**
 * The reactor-style score ring.
 *
 * `value === null` renders a dash, not a number. This matters more than how it looks: a score of
 * 100/100 on a tenant that has never completed a scan is the interface telling the customer they
 * are secure on the strength of having asked nothing. It is the same failure `engine_outcome()`
 * exists to prevent in the scanner, one layer up, and the gauge is where it would have been most
 * convincing.
 */
export function SecurityGauge({ value, caption }: { value: number | null; caption: string }) {
  const size = 132, stroke = 7, r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;
  const pct = value === null ? 0 : Math.max(0, Math.min(100, value)) / 100;

  const color = value === null ? "var(--text-faint)"
    : value >= 85 ? "var(--ok-text)"
    : value >= 60 ? "var(--amber-text)"
    : "var(--plasma)";

  return (
    <div className="gauge" role="img"
         aria-label={value === null ? `${caption}: not calculated` : `${caption}: ${value} of 100`}>
      <svg width={size} height={size} aria-hidden="true">
        <circle className="gauge-track" cx={size / 2} cy={size / 2} r={r}
                fill="none" strokeWidth={stroke} />
        <circle className="gauge-arc" cx={size / 2} cy={size / 2} r={r}
                fill="none" strokeWidth={stroke} stroke={color}
                strokeDasharray={circumference}
                strokeDashoffset={circumference * (1 - pct)} />
      </svg>
      <div className="gauge-core">
        {value === null
          ? <div className="gauge-num unknown">—</div>
          : <div className="gauge-num" style={{ color }}><Counter value={value} /></div>}
        <div className="gauge-cap">{caption}</div>
      </div>
    </div>
  );
}

/* ══ terminal ═════════════════════════════════════════════════════════════════════════════════ */

export interface TermLine { t?: string; text: string; tone?: "ok" | "warn" | "bad" }

/**
 * A live log panel. It renders lines it is given and invents nothing: with real telemetry
 * available there is no reason to print fiction, and a security console that prints fake events
 * has trained its operator to ignore it.
 */
export function TerminalPanel({ title = "system", lines, live }:
  { title?: string; lines: TermLine[]; live?: boolean }) {
  const body = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = body.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines.length]);

  return (
    <div className="terminal">
      <div className="terminal-bar">
        {live && <span className="live-dot" />}
        <span>{title}</span>
      </div>
      <div className="terminal-body" ref={body}>
        {lines.length === 0 && (
          <div className="terminal-line">
            <span className="p">root@security-core:~$</span>
            <span className="m">awaiting events<span className="caret" /></span>
          </div>
        )}
        {lines.map((l, i) => (
          <div className={`terminal-line${l.tone ? ` ${l.tone}` : ""}`} key={i}>
            {l.t && <span className="t">{l.t}</span>}
            <span className="p">›</span>
            <span className="m">{l.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ══ cursor ═══════════════════════════════════════════════════════════════════════════════════ */

/**
 * Targeting cursor, pointer devices only.
 *
 * Mounted behind a `(pointer: fine)` check rather than merely hidden on touch: a listener on
 * every pointermove that exists to move an invisible element is a frame cost with no output. The
 * ring lerps toward the pointer and the dot tracks it exactly, which reads as a system locking
 * on rather than a lagging decoration.
 */
export function TargetingCursor() {
  const ring = useRef<HTMLDivElement>(null);
  const dot = useRef<HTMLDivElement>(null);
  const [enabled] = useState(() =>
    typeof window !== "undefined"
    && typeof window.matchMedia === "function"
    && window.matchMedia("(pointer: fine)").matches
    && !prefersReducedMotion());

  useEffect(() => {
    if (!enabled) return;
    let x = window.innerWidth / 2, y = window.innerHeight / 2;
    let rx = x, ry = y;
    let raf = 0;

    const onMove = (e: PointerEvent) => {
      x = e.clientX; y = e.clientY;
      if (dot.current) dot.current.style.transform = `translate3d(${x}px, ${y}px, 0)`;
      const hot = (e.target as HTMLElement | null)?.closest(
        "button, a, input, select, textarea, [role='button'], .nav-item, .chain-card");
      ring.current?.classList.toggle("hot", !!hot);
    };

    const frame = () => {
      rx += (x - rx) * 0.19;
      ry += (y - ry) * 0.19;
      if (ring.current) ring.current.style.transform = `translate3d(${rx}px, ${ry}px, 0)`;
      raf = requestAnimationFrame(frame);
    };

    window.addEventListener("pointermove", onMove, { passive: true });
    raf = requestAnimationFrame(frame);
    return () => {
      window.removeEventListener("pointermove", onMove);
      cancelAnimationFrame(raf);
    };
  }, [enabled]);

  if (!enabled) return null;
  return (
    <>
      <div className="cursor-ring" ref={ring} aria-hidden="true" />
      <div className="cursor-dot" ref={dot} aria-hidden="true" />
    </>
  );
}

/* ══ live clock ═══════════════════════════════════════════════════════════════════════════════ */

export function SystemClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return <b>{now.toISOString().slice(11, 19)}Z</b>;
}
