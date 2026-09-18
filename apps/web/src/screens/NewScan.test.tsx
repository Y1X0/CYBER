// The guided upload flow for artifact-based scanners (Android/iOS), asserted as customer behaviour.
//
// The brief: the console must not promise an upload it cannot perform, and when it does offer one it
// must validate, show progress, attach the artifact, and only then start the scan. These tests drive
// the real component against a mocked API and assert what the customer sees and what the client calls.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, ARTIFACT_MAX_BYTES, api } from "../api";
import * as router from "../router";
import { NewScanScreen } from "./NewScan";

afterEach(() => vi.restoreAllMocks());

const page = (rows: unknown[]) => ({ rows, hasMore: false, nextCursor: null });
const CUSTOMER = { id: "cust-1", name: "Acme", criticality: "high" };

function apkFile(name = "app.apk", size = 2048): File {
  const f = new File([new Uint8Array(8)], name, { type: "application/octet-stream" });
  Object.defineProperty(f, "size", { value: size });
  return f;
}

async function openAndroidForm() {
  vi.spyOn(api, "customers").mockResolvedValue(page([CUSTOMER]) as never);
  render(<NewScanScreen preselect="android" />);
  // The identifier field is the marker that the scan form (not the chooser) is showing.
  await screen.findByText(/App name or package/i);
}

describe("new scan — artifact upload", () => {
  it("offers a real file picker and honest static-analysis copy for Android", async () => {
    await openAndroidForm();
    expect(screen.getByTestId("artifact-file")).toBeInTheDocument();
    // Honest copy: it says the file is read statically and never run.
    expect(screen.getByText(/read statically and never run/i)).toBeInTheDocument();
  });

  it("rejects a wrong file type before any upload", async () => {
    const upload = vi.spyOn(api, "uploadArtifact");
    await openAndroidForm();
    fireEvent.change(screen.getByTestId("artifact-file"),
      { target: { files: [apkFile("notes.pdf")] } });
    expect(await screen.findByRole("alert")).toHaveTextContent(/needs a \.apk/i);
    expect(upload).not.toHaveBeenCalled();
  });

  it("rejects an oversized file before any upload", async () => {
    const upload = vi.spyOn(api, "uploadArtifact");
    await openAndroidForm();
    fireEvent.change(screen.getByTestId("artifact-file"),
      { target: { files: [apkFile("big.apk", ARTIFACT_MAX_BYTES + 1)] } });
    expect(await screen.findByRole("alert")).toHaveTextContent(/limit/i);
    expect(upload).not.toHaveBeenCalled();
  });

  it("uploads the artifact, then starts the scan, then routes to it", async () => {
    const created = { id: "asset-9", customer_id: "cust-1", name: "app", kind: "mobile_app",
      identifier: "", exposure: "isolated" };
    vi.spyOn(api, "createAsset").mockResolvedValue(created as never);
    const upload = vi.spyOn(api, "uploadArtifact").mockResolvedValue({ id: "art-1" } as never);
    const start = vi.spyOn(api, "startScan").mockResolvedValue({ id: "scan-7" } as never);
    const nav = vi.spyOn(router, "navigate").mockImplementation(() => {});
    await openAndroidForm();

    fireEvent.change(screen.getByTestId("artifact-file"), { target: { files: [apkFile()] } });
    fireEvent.click(screen.getByRole("button", { name: /upload & scan/i }));

    await waitFor(() => expect(start).toHaveBeenCalledWith("asset-9", ["mobile"]));
    // The artifact was uploaded to the created asset BEFORE the scan started.
    expect(upload).toHaveBeenCalledWith("asset-9", expect.any(File), expect.any(Function));
    const uploadOrder = upload.mock.invocationCallOrder[0];
    const startOrder = start.mock.invocationCallOrder[0];
    expect(uploadOrder).toBeLessThan(startOrder);
    expect(nav).toHaveBeenCalledWith("scans/scan-7");
  });

  it("surfaces a server upload rejection and does not start the scan", async () => {
    vi.spyOn(api, "createAsset").mockResolvedValue({ id: "asset-9", customer_id: "cust-1",
      name: "app", kind: "mobile_app", identifier: "", exposure: "isolated" } as never);
    vi.spyOn(api, "uploadArtifact").mockRejectedValue(new Error("the file is too large (limit 100 MB)"));
    const start = vi.spyOn(api, "startScan").mockResolvedValue({ id: "scan-7" } as never);
    await openAndroidForm();

    fireEvent.change(screen.getByTestId("artifact-file"), { target: { files: [apkFile()] } });
    fireEvent.click(screen.getByRole("button", { name: /upload & scan/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/too large/i);
    expect(start).not.toHaveBeenCalled();
  });

  it("shows no file picker for a URL-based scanner (Website)", async () => {
    vi.spyOn(api, "customers").mockResolvedValue(page([CUSTOMER]) as never);
    vi.spyOn(api, "ownerDirectPreflight").mockResolvedValue({ eligible: false } as never);
    render(<NewScanScreen preselect="website" />);
    await screen.findByText(/Website URL/i);
    expect(screen.queryByTestId("artifact-file")).not.toBeInTheDocument();
  });
});

describe("new scan — owner-direct", () => {
  async function openWebsiteForm(eligible: boolean) {
    vi.spyOn(api, "customers").mockResolvedValue(page([CUSTOMER]) as never);
    vi.spyOn(api, "ownerDirectPreflight").mockResolvedValue({ eligible } as never);
    render(<NewScanScreen preselect="website" />);
    await screen.findByText(/Website URL/i);
  }

  it("hides the owner-direct control when the caller is not eligible", async () => {
    await openWebsiteForm(false);
    expect(screen.queryByTestId("owner-direct")).not.toBeInTheDocument();
  });

  it("reuses the existing asset when the target already exists (409), instead of dead-ending", async () => {
    await openWebsiteForm(false);
    // createAsset reports the target already exists; the flow should scan the named existing asset.
    vi.spyOn(api, "createAsset").mockRejectedValue(new ApiError(409, "asset already exists", {
      code: "asset_exists", asset_id: "asset-existing" }));
    const start = vi.spyOn(api, "startScan").mockResolvedValue({ id: "scan-9" } as never);
    const nav = vi.spyOn(router, "navigate").mockImplementation(() => {});

    fireEvent.change(screen.getByLabelText(/Website URL/i),
      { target: { value: "https://sallehly.com/" } });
    fireEvent.click(screen.getByRole("button", { name: /start scan/i }));

    await waitFor(() => expect(start).toHaveBeenCalledWith("asset-existing", ["dast"]));
    expect(nav).toHaveBeenCalledWith("scans/scan-9");
  });

  it("offers owner-direct, then requires the affirmation before scanning", async () => {
    await openWebsiteForm(true);
    vi.spyOn(api, "createAsset").mockResolvedValue(
      { id: "asset-3", customer_id: "cust-1", name: "site", kind: "web",
        identifier: "https://example.com", exposure: "public" } as never);
    const nav = vi.spyOn(router, "navigate").mockImplementation(() => {});
    // First dispatch (affirm=false) is refused with the affirmation-required 409; the second
    // (affirm=true) succeeds. This is the server-driven affirmation step.
    const start = vi.spyOn(api, "startScan")
      .mockRejectedValueOnce(new ApiError(409, "affirmation required", {
        code: "owner_direct_affirmation_required", target: "https://example.com",
        affirmation: "I affirm I have the legal right to scan https://example.com.",
      }))
      .mockResolvedValueOnce({ id: "scan-3" } as never);

    // Eligible → the control appears; opt in, fill the URL, and start.
    fireEvent.click(await screen.findByTestId("owner-direct"));
    fireEvent.change(screen.getByLabelText(/Website URL/i),
      { target: { value: "https://example.com" } });
    fireEvent.click(screen.getByRole("button", { name: /start scan/i }));

    // The affirmation modal appears rather than a raw error, carrying the server's exact text.
    expect(await screen.findByText(/Confirm owner-direct scan/i)).toBeInTheDocument();
    expect(screen.getByText(/legal right to scan https:\/\/example\.com/i)).toBeInTheDocument();

    // Affirm, then confirm — the second dispatch carries affirm=true against the same asset.
    fireEvent.click(screen.getByTestId("affirm-check"));
    fireEvent.click(screen.getByRole("button", { name: /affirm & scan/i }));

    await waitFor(() => expect(start).toHaveBeenLastCalledWith(
      "asset-3", ["dast"], { direct: true, affirm: true }));
    expect(nav).toHaveBeenCalledWith("scans/scan-3");
  });
});
