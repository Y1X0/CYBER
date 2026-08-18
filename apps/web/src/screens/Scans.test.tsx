// The scan screen's one job: never let a customer read "no findings" as "you are clean" when an
// engine did not answer.

import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import { ScanDetailScreen } from "./Scans";

const scan = (status: string) => ({
  id: "11111111-2222-3333-4444-555555555555",
  customer_id: "c", asset_id: "a", status, trigger: "manual",
  requested_engines: ["secrets", "sast"], stats: { total: 0 },
  started_at: null, finished_at: null, created_at: "2026-01-01T00:00:00Z",
});

const engine = (name: string, state: string, extra: Record<string, unknown> = {}) => ({
  engine: name, status: state === "checked" ? "completed" : "failed",
  customer_state: state, meaning: `meaning for ${name}`,
  error: null, degraded: false, missing: [], started_at: null, ...extra,
});

afterEach(() => vi.restoreAllMocks());

function stub(opts: {
  status: string;
  engines: ReturnType<typeof engine>[];
  findings?: unknown[];
}) {
  vi.spyOn(api, "scan").mockResolvedValue(scan(opts.status) as never);
  vi.spyOn(api, "scanEngines").mockResolvedValue(opts.engines as never);
  vi.spyOn(api, "findings").mockResolvedValue(
    { rows: opts.findings ?? [], hasMore: false, nextCursor: null } as never);
  vi.spyOn(api, "queueHealth").mockResolvedValue({
    state: "idle", detail: "Nothing is queued or running for you right now.",
    queued: 0, running: 0, oldest_waiting_seconds: 0,
    scanner: { status: "unknown", detail: "" },
  } as never);
}

describe("scan detail", () => {
  it("calls an empty result clean only when every engine actually ran", async () => {
    stub({ status: "completed", engines: [engine("secrets", "checked"), engine("sast", "checked")] });

    render(<ScanDetailScreen id="s1" />);

    expect(await screen.findByText("No findings")).toBeInTheDocument();
    expect(screen.getByText(/this asset is clean/i)).toBeInTheDocument();
  });

  it("refuses to call an empty result clean when an engine did not run", async () => {
    stub({
      status: "partial",
      engines: [
        engine("secrets", "checked"),
        engine("sast", "not_checked", { error: "semgrep exploded" }),
      ],
    });

    render(<ScanDetailScreen id="s1" />);

    // The headline itself must carry the caveat — a customer skimming must not take away "clean".
    expect(await screen.findByText(/not a clean result/i)).toBeInTheDocument();
    expect(screen.getByText(/1 did not run at all \(sast\)/i)).toBeInTheDocument();
    expect(screen.queryByText(/this asset is clean/i)).not.toBeInTheDocument();
  });

  it("treats a degraded engine as inconclusive rather than clean", async () => {
    stub({
      status: "completed",
      engines: [
        engine("secrets", "checked"),
        engine("sast", "inconclusive", { degraded: true, missing: ["semgrep"] }),
      ],
    });

    render(<ScanDetailScreen id="s1" />);

    expect(await screen.findByText(/not a clean result/i)).toBeInTheDocument();
    expect(screen.getByText(/ran with reduced coverage/i)).toBeInTheDocument();
  });

  it("does not describe an unfinished scan as having no findings", async () => {
    stub({ status: "queued", engines: [] });

    render(<ScanDetailScreen id="s1" />);

    expect(await screen.findByText("No findings yet")).toBeInTheDocument();
    expect(screen.getByText(/has not finished/i)).toBeInTheDocument();
  });

  it("explains a queued scan when the scanner is not executing anything", async () => {
    vi.spyOn(api, "scan").mockResolvedValue(scan("queued") as never);
    vi.spyOn(api, "scanEngines").mockResolvedValue([] as never);
    vi.spyOn(api, "findings").mockResolvedValue(
      { rows: [], hasMore: false, nextCursor: null } as never);
    vi.spyOn(api, "queueHealth").mockResolvedValue({
      state: "stalled",
      detail: "Guardian has accepted your scan but nothing is executing it.",
      queued: 1, running: 0, oldest_waiting_seconds: 900,
      scanner: { status: "degraded", detail: "the scanner has stopped executing" },
    } as never);

    render(<ScanDetailScreen id="s1" />);

    expect(await screen.findByText(/waiting and nothing is executing/i)).toBeInTheDocument();
    expect(screen.getByText(/nothing is executing it/i)).toBeInTheDocument();
    // No fabricated progress, and no claim of a result.
    expect(screen.getByText(/No result has been produced/i)).toBeInTheDocument();
  });

  it("shows each engine's outcome and the reason it failed", async () => {
    stub({
      status: "partial",
      engines: [engine("cspm", "not_checked", { error: "no cloud snapshot is configured" })],
    });

    render(<ScanDetailScreen id="s1" />);

    await waitFor(() => expect(screen.getByText("cspm")).toBeInTheDocument());
    expect(screen.getByText("Not checked")).toBeInTheDocument();
    expect(screen.getByText(/no cloud snapshot is configured/i)).toBeInTheDocument();
  });

  it("surfaces the server's error rather than an empty screen", async () => {
    vi.spyOn(api, "scan").mockRejectedValue(new Error("database is unreachable"));
    vi.spyOn(api, "scanEngines").mockResolvedValue([] as never);
    vi.spyOn(api, "findings").mockResolvedValue(
      { rows: [], hasMore: false, nextCursor: null } as never);
    vi.spyOn(api, "queueHealth").mockResolvedValue({} as never);

    render(<ScanDetailScreen id="s1" />);

    expect(await screen.findByText("This could not be loaded")).toBeInTheDocument();
    expect(screen.getByText("database is unreachable")).toBeInTheDocument();
    expect(screen.getByText(/failure to ask, not an answer/i)).toBeInTheDocument();
  });
});
