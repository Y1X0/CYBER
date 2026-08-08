# ADR-018 — Provider #2: PCAP / Artifact Analysis (offline, asset-anchored, non-network)

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

Provider #1 (ADR-017) proved the *active/network* branch of the tool rail (authorization → human
approval → egress → sandbox → evidence → finding → graph). The rail still had an unproven, and more
dangerous, branch: **parsing an untrusted artifact**. That is where most security platforms are
compromised (zip bombs, parser CVEs, decompression bombs, path traversal). Proving
`Artifact → Sandbox Parser → Evidence → Finding → Graph` — with **no network at all** — is the right
next step before any active network tool (Nmap), so that Nmap later is just another governed
Provider, not a re-architecture.

A network-target authorization model does not fit an artifact: an artifact is not a host. The
locked decision is **asset-anchored** authorization — an artifact is analyzed on behalf of an asset
the tenant is authorized to assess — and the artifact is **never** treated as a network target.

## Decision (CTO-locked)

Ship **`pcap_meta`**, an offline PCAP *header/metadata-only* analyzer, on the ADR-016 rail. It reuses
`ToolJob`/sandbox/evidence-hash-chain/`Scan`/`ScanEngineRun`/`to_finding`/6E `enrich_graph`. No
migration; DB head stays `0009_phase6c_recon`.

1. **Passive, offline, stdlib-only.** Capabilities: `network=False, active=False, destructive=False,
   requires_authorization=True, requires_human_approval=False`. The parser is pure `struct` (no
   Scapy, no external dependency); the execution plane runs it with the network fully denied. It
   reads only: the global header, per-record headers, and enough of each frame's L2/L3/L4 *headers*
   to observe endpoints, ports, and protocol. **Never** payload, reassembly, content extraction,
   crawling, DNS, or any socket.
2. **Asset-anchored authorization (the anchor is not a network target).** The trusted plane verifies
   the asset exists, is owned by the tenant, and carries a valid `Authorization` (`asset_id ==` the
   asset). The asset id is placed into the `EffectiveScope` as the authorization *anchor* purely so
   the policy gate's "authorization ⇒ in-scope target" invariant holds; because `network=False`, the
   execution plane never uses it as an egress target. A missing / unowned / unauthorized asset is
   **denied before anything executes**. The shared scope/gate logic is reused unchanged (a dedicated
   `dispatch_artifact_job` supplies the asset anchor).
3. **Inline-bounded transport, no object storage.** The raw artifact travels base64 inside the
   `ToolJob` (result-return), capped at **2 MB**. A larger, empty, or undecodable blob is **rejected
   fail-closed before execution**. No object storage, no `artifacts` table, no migration.
4. **Fail-closed, no partial success.** A bad magic, a truncated global/record header, truncated
   packet data, pcapng, or exceeding the packet bound fails the whole capture: the artifact
   descriptor is marked `failed`/`rejected` and **no** flow evidence and **no** finding are produced.
   A single exotic frame that cannot be dissected is counted but yields no endpoints — it never fails
   the capture. Byte and packet bounds prevent unbounded loops.
5. **Evidence-first, chain of custody.** The first evidence item describes the artifact itself
   (`sha256` of the raw bytes, size, media type) with an empty `occurred_at` so it sorts to the
   **root** of the tenant hash chain. A finding is a derived inference from evidence, never the tool's
   verdict; a benign capture yields evidence with zero findings (evidence-only, no empty Scan).
6. **Observation, not discovery.** Endpoints seen inside the capture are recorded as *observed
   endpoints in evidence only*. The provider NEVER creates an asset for them, and never probes,
   resolves, reverse-resolves, connects to, or scans them. Populating the world model from capture
   endpoints is a future World-Model concern with its own binding rules — Provider #2 does not invent
   the world.
7. **Conservative, evidence-backed findings only.** `normalize()` emits a finding solely for a
   directly observed cleartext protocol on a well-known port (HTTP/FTP/Telnet/SMTP/POP3/IMAP), tagged
   CWE-319, severity MEDIUM, and traceable to `artifact_sha256` + endpoints + port + window
   (`Finding ← Evidence ← Artifact`). No inference of compromise/exposure from metadata; no AI.
8. **Findings bound to the anchored asset**, then 6E enrich yields `asset --exposes--> finding`.
   `EngineKey.PCAP_META` is added (additive) so the finding fingerprint and the `ScanEngineRun`
   engine label agree.

## Alternatives considered

- **Full PCAP dissection via Scapy.** Rejected: a large dependency and a CVE surface of its own;
  header-only `struct` parsing proves the untrusted-input branch with zero dependencies.
- **Model the artifact as a network target / new tool-scope table.** Rejected: an artifact is not a
  host; asset-anchored authorization reuses the existing gate without widening the scope model.
- **Object storage / `artifacts` table for the blob.** Rejected for Phase 2: a migration and new
  infrastructure. Inline-bounded (≤2 MB) proves the rail; object storage is a later, separate phase.
- **Auto-create assets / probe endpoints found in the capture.** Rejected outright: that turns an
  analyzer into an active discovery/scanning tool — the exact boundary this provider must hold.

## Consequences

- The rail is now proven on **both** branches: active-network (Provider #1) and non-network
  untrusted-artifact (Provider #2) — sandboxing, authorization, human-approval boundary, evidence
  hash chain, asset binding, findings, and graph integration all exercised two different ways.
- A compromise inside the parser finds no DB, no KMS, no network, and no other tenant.
- 6C.4/6D/6E/6F/Framework P1/Provider #1 are untouched; DB head stays `0009_phase6c_recon`.

### Deferred / technical debt (not in Phase 2)

- Object storage / an `artifacts` table and analysis of artifacts larger than 2 MB.
- Populating the world model from observed capture endpoints (needs a binding rule + evidence
  threshold) — a future World-Model / Provider concern.
- Additional artifact types (archives, SBOM, logs) and richer protocol facts; IPv6 extension-header
  walking; link types beyond Ethernet/RAW/NULL/Linux-SLL.
- Backlinking an `EvidenceItem` to the Finding it justified (still null — evidence precedes findings).
- Everything already deferred by ADR-011…017.
