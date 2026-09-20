// A sleeping free-tier backend must never read as a failure or a stuck scan.
//
// The control plane sleeps when idle, and the first request against a cold instance is rejected
// before any HTTP status exists — the client surfaces that as `ApiError(status: 0)`. These tests
// pin the three properties that keep it from looking like something it is not: it is classified as
// "waking" (not "error"), the UI shows a waking state and rides out the cold start, and a *real*
// failure (any non-zero status) still shows the honest error state.

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "./api";
import { Async, isBackendWaking, useAsync } from "./ui";

function Harness({ fn }: { fn: () => Promise<string> }) {
  const loader = useAsync(fn, []);
  return <Async loader={loader}>{(d) => <div>loaded: {d}</div>}</Async>;
}

describe("isBackendWaking", () => {
  it("is true only for a status-0 ApiError (an unreachable backend)", () => {
    expect(isBackendWaking(new ApiError(0, "could not reach"))).toBe(true);
    expect(isBackendWaking(new ApiError(503, "database down"))).toBe(false);
    expect(isBackendWaking(new Error("boom"))).toBe(false);
    expect(isBackendWaking(null)).toBe(false);
  });
});

describe("useAsync against a sleeping backend", () => {
  it("shows a waking state, not an error, when the backend is unreachable", async () => {
    const fn = vi.fn<() => Promise<string>>().mockRejectedValue(new ApiError(0, "unreachable"));
    render(<Harness fn={fn} />);
    expect(await screen.findByText(/backend is waking up/i)).toBeInTheDocument();
    // The single thing this must never do: call a sleeping instance a failure.
    expect(screen.queryByText(/this could not be loaded/i)).not.toBeInTheDocument();
  });

  it("recovers on its own once the backend answers", async () => {
    const fn = vi.fn<() => Promise<string>>()
      .mockRejectedValueOnce(new ApiError(0, "cold start"))
      .mockResolvedValue("live");
    render(<Harness fn={fn} />);
    await screen.findByText(/backend is waking up/i);
    // The first retry fires after the backoff; the page repaints itself with no user action.
    expect(await screen.findByText(/loaded: live/i, {}, { timeout: 4000 })).toBeInTheDocument();
    expect(fn).toHaveBeenCalledTimes(2);
  }, 6000);

  it("still shows the honest error state for a real (non-zero) failure", async () => {
    const fn = vi.fn<() => Promise<string>>().mockRejectedValue(new ApiError(503, "database down"));
    render(<Harness fn={fn} />);
    expect(await screen.findByText(/this could not be loaded/i)).toBeInTheDocument();
    expect(screen.getByText(/database down/i)).toBeInTheDocument();
    expect(screen.queryByText(/backend is waking up/i)).not.toBeInTheDocument();
  });
});
