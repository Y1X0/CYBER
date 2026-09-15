# Tooling feasibility study — expanding Guardian's security toolset

> دراسة جدوى لتوسيع أدوات المنصة. هدفها: نعرف بالضبط أي أداة نضيف، بأي ترتيب، وكيف — بحيث
> لما نقول "ابدأ"، يكون كل قرار متّخذ مسبقاً. مبنية على الإطار الموجود فعلاً في المشروع، مش على
> فراغ.

Status: planning. Nothing here is built by this document. It is the map the build follows.

---

## 0. الخلاصة بالعربي (read this first)

المنصة **ما ينقصها إطار** — ينقصها أدوات مركّبة داخل الإطار. الفرق مهم:

- في **سجل أدوات** (`guardian.tool_providers`) أي أداة بتنضاف كـ plug-in بدون تعديل النواة.
- في **بوابة حوكمة** بتقرر مين مسموح يشغّل شو، قبل ما الأداة تشتغل — بمستويات L0 لـ L5.
- في **صندوق معزول على مستوى نواة لينكس** (`uid_nft`) — حتى لو أداة انخرقت بالكامل، ما بتقدر
  تبعت حزمة برّا النطاق المصرّح.
- في **سجل تراخيص** فيه ٦١ أداة مدروسة قانونياً — مع حالة كل وحدة (تنفع تجارياً / محتاجة مراجعة /
  ممنوعة).
- في **خدمة AI** جاهزة مع مزوّد Claude وحواجز ضد حقن التعليمات — بس مطفية لأنها محتاجة مفتاح.

يعني الشغل مش "ابنِ نظام أدوات". الشغل: **اكتب مزوّد لكل أداة، صنّفها، رخّصها، وركّبها.**

المشكلة الوحيدة الحقيقية اللي بتحكم بالترتيب هي **أين تشتغل**:

| المستوى | مثال | بيشتغل على المضيف المجاني الحالي؟ |
|---|---|---|
| تحليل بلا شبكة (L0) | فحص PCAP، تحليل ملف، فحص إعداد | ✅ نعم، فوراً |
| شبكة سلبية (L1) | استعلام CT، DNS، جلب رأس HTTP | ✅ نعم |
| استطلاع نشط (L2) | nmap، فحص منافذ، DAST | ❌ لأ — بدّه مضيف فيه `CAP_NET_ADMIN` |
| حساس/استغلال (L3–L5) | حقن، اختبار اعتماد، استغلال | ❌ لأ — بدّه المضيف + حملة + موافقة بشرية |

القرار الاستراتيجي: **ابدأ بالطبقة اللي بتشتغل على المضيف الحالي (L0/L1)** — فيها عشرات الأدوات
القيّمة (تحليل جنائي، فحص ثغرات ثابت، أسرار، حاويات، سحابة، PCAP زي Wireshark). طبقة الشبكة النشطة
(L2+) لازمها مضيف تاني، وهي **قرار منفصل** مربوط بـ BLOCKER-1.

عن الـ AI و"يكتشف ثغرة مش موجودة": في جزء حقيقي وجزء وهم، وأنا بفصّلهم بصدق في القسم 6 — لأن أسوأ
شي في منتج أمني إنه يوعد باكتشاف سحري ويطلع صفر.

---

## 1. The seam every tool plugs into

Before cataloguing tools, here is exactly how one is added, because every row in the catalogue is
an instance of this and the effort estimates are relative to it.

A tool is a class implementing `ToolProvider` (`packages/common/.../ports.py`), registered under the
`guardian.tool_providers` entry-point group in `pyproject.toml`. It declares four things and
implements four methods:

```python
class ToolProvider(Protocol):
    key: str          # stable id, e.g. "gitleaks"
    name: str
    version: str

    @property
    def capabilities(self) -> ToolCapabilities: ...   # WHAT it is — read by the policy gate
    def validate(self, job: ToolJob) -> None: ...     # reject a malformed job (NOT authorization)
    def execute(self, job: ToolJob) -> Iterable[RawEvidence]: ...  # run in the sandbox, no DB
    def normalize(self, evidence) -> RawFinding | None: ...        # evidence → canonical finding
```

`ToolCapabilities` is the whole governance contract in one object:

```python
category: str            # "network_discovery" | "web_assessment" | "forensics" | ...
network: bool            # opens outbound network?
active: bool             # actively touches a target (vs passive/analytical)?
destructive: bool        # can change target state? (never runs without approval)
requires_authorization   # needs a DB-backed authorization?
requires_human_approval  # needs an explicit human sign-off before running?
supported_targets, ports, protocols
```

From those primitives, `derive_capability_level()` assigns L0–L5 **deterministically**:

| Level | Name | Trigger | Extra gate |
|---|---|---|---|
| L0 | PASSIVE_ANALYSIS | offline, analytical | authorization only |
| L1 | PASSIVE_NETWORK | `network=True`, not active | authorization |
| L2 | ACTIVE_RECON | `active=True` | authorization |
| L3 | SENSITIVE | category ∈ {credential, auth_testing, web_checks} | **campaign + approval** |
| L4 | EXPLOIT_VALIDATION | category ∈ {exploit} | campaign + **independent** approval |
| L5 | DESTRUCTIVE | `destructive=True` | campaign + independent approval |

So **adding a tool is: write the class, declare its capabilities honestly, register it, add its
licence row, add tests.** The level and the gate follow from the declaration automatically. This is
the single most important fact in this study: the hard part (governance, isolation, audit) is
already built. Adding a tool is filling a known shape.

### The two execution planes

- **In-process backend** (`backends/inproc.py`) — offline or fixed-endpoint work, runs in the
  worker. No special privilege. **This is what the Render free host can run today.**
- **uid_nft backend** (`backends/uid_nft.py`) — any external binary that touches the network. Each
  run gets a throwaway unprivileged uid and a private nftables table that drops every packet
  outside the authorized scope. **Requires `CAP_NET_ADMIN`; the Render host does not have it.**

An engine whose tool is absent reports `not_checked`, never `clean` — this is `engine_outcome()`,
and it means shipping tools incrementally is safe: a missing tool degrades a report honestly rather
than lying.

---

## 2. How to read the catalogue

Every tool below carries these columns — this is the "header row" the study is built around:

- **Tool** — the binary or library.
- **Level** — L0–L5, derived as above. Determines the gate and the host.
- **Licence** — from `docs/TOOL_LICENSES.md` where already reviewed, or a new verdict.
  `APPROVED` = ship freely · `SEP-PROC` = copyleft but invoked as a separate process · `REVIEW` =
  needs counsel · `PROHIBITED` = never (usually AGPL for a SaaS).
- **Plane** — `offline` (in-proc, no net) · `net-inproc` (fixed endpoint) · `uid_nft` (external
  binary, privileged host) · `cloud-api` (talks to a provider API with customer creds).
- **Host** — `free` (runs on the current Render host) · `worker` (needs a CAP_NET_ADMIN host).
- **AI** — where an LLM adds real value on top of this tool (see §6 for the honest limits).
- **Effort** — S/M/L to write the provider, relative to the seam in §1.
- **Priority** — P0 (do first) … P3 (later / needs a decision).

Legend for the compact tables: level, licence, plane, host, effort, priority.

---

## 3. Catalogue — offline & passive (P0/P1, runs on the current host)

**This whole section runs on the free Render deployment today.** No new infrastructure. This is
where the build should start.

### 3.1 Digital forensics — artifact & file analysis (الأدلة الجنائية)

The user named forensics specifically. Almost all of it is offline analysis of an uploaded
artifact — a perfect fit for L0 and the current host.

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **file-type / magic analysis** (stdlib + `python-magic`) | L0 | BSD | offline | free | S | P0 |
| **EXIF / document metadata** (author, GPS, software, timestamps) | L0 | own code | offline | free | M | P0 |
| **PE / ELF / Mach-O header analysis** (imports, sections, entropy) | L0 | own code | offline | free | M | P1 |
| **hash & fuzzy hash** (SHA-256, ssdeep/TLSH for similarity) | L0 | Apache/BSD | offline | free | S | P0 |
| **archive inspection** (nested zip/tar, zip-bomb guard, embedded files) | L0 | stdlib | offline | free | M | P1 |
| **Office/PDF macro & object extraction** (`oletools`, `pdfid`) | L0 | own/BSD | offline | free | M | P1 |
| **YARA rule matching** over uploaded artifacts | L0 | BSD-3 | offline | free | M | P0 |
| **timeline builder** (MACB from filesystem metadata / logs) | L0 | own code | offline | free | L | P2 |
| **memory-image triage** (Volatility3 process/dll/netscan) | L0 | Volatility SL | offline | free* | L | P3 |

`python-magic`, YARA, and hashing are the strongest P0 forensics wins: small providers, huge
analytical value, zero network, zero licence risk. Volatility3 is marked P3 not for licence but for
weight — memory images are large and the free host has a small disk allowance (§7).

**AI dimension:** the LLM is genuinely useful here — given YARA hits + strings + PE imports, it can
explain *what a sample likely does and why*, cluster related artifacts, and draft an incident note.
It is explaining structured evidence, which is where LLMs are trustworthy (§6).

### 3.2 Network forensics — PCAP (Wireshark family, named by the user)

Wireshark's own engine ships as `tshark`. Guardian already has an **offline PCAP metadata provider**
(`pcap_provider.py`) — the seam exists. Expansion:

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **PCAP metadata** (existing — flows, talkers, ports, timing) | L0 | own | offline | free | — | done |
| **tshark protocol dissection** (DNS, HTTP, TLS SNI, creds-in-clear) | L0 | GPL-2.0 | offline (sep-proc) | free | M | P1 |
| **Zeek offline log generation** from a PCAP (conn/dns/http/ssl logs) | L0 | BSD-3 | offline | free | L | P2 |
| **Suricata offline replay** (IDS alerts from a PCAP + ruleset) | L0 | GPL-2.0 | offline (sep-proc) | free | L | P2 |
| **extract-artifacts-from-PCAP** (files carved from streams, then §3.1) | L0 | own | offline | free | M | P2 |

Wireshark/tshark is **GPL-2.0** → `SEP-PROC`: invoke the binary, never link, no shipping modified
source. That is the same posture already approved for sqlmap and Nikto, so it is a solved licence
pattern, not a new risk. Zeek (BSD) is the cleanest and the most powerful for turning a capture into
structured findings.

**AI dimension:** strong. Zeek logs + Suricata alerts are exactly the structured, high-signal input
an LLM can narrate into "here is the likely intrusion story, here is what to pull next."

### 3.3 Static application security testing (SAST) — code

Guardian has a `SastEngine` already. These are the binaries behind a real SAST.

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **semgrep / opengrep** (multi-language, rule-based) | L0 | LGPL-2.1 | offline (sep-proc) | free | M | P0 |
| **bandit** (Python) | L0 | Apache-2.0 | offline | free | S | P0 |
| **gosec** (Go) | L0 | Apache-2.0 | offline (sep-proc) | free | S | P1 |
| **njsscan / eslint-security** (JS/TS) | L0 | MIT | offline (sep-proc) | free | M | P1 |
| **brakeman** (Ruby/Rails) | L0 | MIT-ish | offline (sep-proc) | free | M | P2 |
| **CodeQL** | L0 | Proprietary | — | — | — | **PROHIBITED** |

opengrep (the community LGPL fork of semgrep) is the P0 pick precisely because it avoids semgrep's
licence-change uncertainty. CodeQL stays out — free only for open source; commercial use needs a
GitHub licence.

**AI dimension:** this is the single best AI fit in the product. A semgrep hit is a location and a
rule id; an LLM reads the surrounding function and says *whether it is actually exploitable, on what
input, and how to fix it* — turning a noisy rule match into a triaged finding. This is real,
shippable value and it is the honest version of "AI finds vulnerabilities" (§6).

### 3.4 Dependencies / SBOM / supply chain (SCA)

`ScaEngine` exists; trivy/syft/grype are already licence-approved and already fetched in the build.

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **trivy** (deps, OS pkgs, IaC, secrets, SBOM) | L0 | Apache-2.0 | offline | free | — | in use |
| **osv-scanner** (OSV database matching) | L0 | Apache-2.0 | offline | free | S | P0 |
| **syft** (SBOM generation) | L0 | Apache-2.0 | offline | free | S | P1 |
| **grype** (SBOM → vulns) | L0 | Apache-2.0 | offline | free | S | P1 |
| **cosign / SLSA provenance verify** | L0 | Apache-2.0 | offline | free | M | P2 |
| **capslock / dependency-capability analysis** | L0 | Apache-2.0 | offline | free | L | P3 |

All Apache-2.0, all offline, all free-host. This is the lowest-risk category in the study.

### 3.5 Secrets

`SecretsEngine` exists.

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **gitleaks** (git history + tree) | L0 | MIT | offline | free | S | P0 |
| **detect-secrets** (baseline model, entropy) | L0 | Apache-2.0 | offline | free | S | P1 |
| **TruffleHog** | L1 | AGPL-3.0 | — | — | — | **PROHIBITED** |
| **own verifier** (does a found key still work? — carefully, opt-in) | L3 | own | net-inproc | worker | L | P3 |

Note the split: **detecting** a secret is offline L0 and free. **Verifying** a secret is live
(actually authenticating with someone's key), which is L3, needs the worker host, a campaign, and
explicit approval — and replaces TruffleHog's AGPL-blocked verification with a governed equivalent.

### 3.6 Infrastructure-as-code & configuration

`IacEngine` exists.

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **checkov** (Terraform, CFN, K8s, ARM) | L0 | Apache-2.0 | offline | free | S | P0 |
| **KICS** | L0 | Apache-2.0 | offline | free | M | P1 |
| **tfsec / trivy-config** | L0 | Apache-2.0 | offline | free | S | P1 |
| **hadolint** (Dockerfile) | L0 | GPL-3.0 | offline (sep-proc) | free | S | P2 |
| **kube-linter** | L0 | Apache-2.0 | offline | free | M | P2 |

### 3.7 Cloud posture (CSPM / CIEM) — offline-against-an-export, or cloud-API

`CspmEngine` and `K8sEngine` exist. Two sub-modes:

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **Prowler** (AWS/Azure/GCP, CIS/NIST/PCI) | L1 | Apache-2.0 | cloud-api | free¹ | L | P1 |
| **ScoutSuite** | L1 | GPL-2.0 | cloud-api | free¹ | M | P2 |
| **Kubescape** (K8s posture + RBAC) | L1 | Apache-2.0 | cloud-api/offline | free¹ | M | P1 |
| **kube-bench** (CIS K8s) | L0 | Apache-2.0 | offline | free | S | P2 |
| **PMapper** (IAM priv-esc paths) | L0 | Apache-2.0 | offline | free | L | P2 |
| **cartography** (asset graph) | L1 | Apache-2.0 | cloud-api | worker² | L | P3 |

¹ Cloud posture "network" is HTTPS to the provider's API with the **customer's read-only role** — it
is not host-network scanning, so it can run in-process on the free host. The gating question is not
CPU, it is **credential custody**: holding a customer's cloud role is a serious responsibility and
needs the KMS-sealed credential path (which exists) plus an explicit trust decision. Marked P1 but
with a credential-handling review as a precondition.
² cartography builds a large graph DB — disk-bound, so worker host.

**AI dimension:** high. PMapper/cartography produce a graph of "who can reach what"; an LLM turns a
privilege-escalation path into a plain-language attack narrative and a prioritized fix.

---

## 4. Catalogue — active network (needs the worker host; ties to BLOCKER-1)

**None of this runs on the current free host.** It needs a machine with `CAP_NET_ADMIN` and kernel
nftables so the `uid_nft` sandbox can confine each run. That machine is the same unmet need as
BLOCKER-1 (a permanent worker host). So this whole section is **gated on one infrastructure
decision**, and should not be started until that host exists — otherwise every tool here reports
`not_checked` and the work is invisible.

### 4.1 Reconnaissance / attack surface / OSINT

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **subfinder** (passive subdomain) | L1 | MIT | net-inproc | worker | M | P1 |
| **amass** (deep enum) | L2 | Apache-2.0 | uid_nft | worker | M | P2 |
| **dnsx** (bulk DNS) | L1 | MIT | net-inproc | worker | S | P1 |
| **httpx** (HTTP probe/fingerprint) | L2 | MIT | uid_nft | worker | S | P1 |
| **katana** (crawler) | L2 | MIT | uid_nft | worker | M | P2 |
| **CT surface** (existing) | L1 | own | net-inproc | free | — | done |
| **theHarvester / OSINT email-host** | L1 | GPL-2.0 | net-inproc | worker | M | P3 |

### 4.2 Network scanning / port / service

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **nmap** (existing wrapper) | L2 | NPSL | uid_nft | worker | — | **REVIEW** |
| **naabu** (port discovery) | L2 | MIT | uid_nft | worker | M | P1 |
| **fingerprintx** (service fp, no nmap) | L2 | MIT | uid_nft | worker | M | P1 |
| **ZMap** (internet-scale, masscan substitute) | L2 | Apache-2.0 | uid_nft | worker | M | P3 |
| **masscan** | L2 | AGPL-3.0 | — | — | — | **PROHIBITED** |

nmap's wrapper already exists but the **binary must not ship** until the NPSL commercial licence
clears (`LEGAL_REVIEW`). naabu + fingerprintx (both MIT) are the shippable substitutes and should be
the P1 network pair, not nmap.

### 4.3 Web application & API (DAST)

`DastEngine` and `ApiEngine` exist; `web_checks` (L3 templated) exists.

| Tool | Level | Licence | Plane | Host | Effort | Prio |
|---|---|---|---|---|---|---|
| **nuclei format** (existing — native template reader) | L2/L3 | MIT | net-inproc | worker | — | done |
| **OWASP ZAP** (full DAST, active scan) | L3 | Apache-2.0 | uid_nft | worker | L | P2 |
| **ffuf** (content discovery / fuzzing) | L3 | MIT | uid_nft | worker | M | P2 |
| **dalfox** (XSS) | L3 | MIT | uid_nft | worker | M | P2 |
| **Schemathesis** (API property testing from OpenAPI) | L3 | MIT | uid_nft | worker | M | P2 |
| **sqlmap** (SQLi) | L4 | GPL-2.0 | uid_nft (sep-proc) | worker | L | P3 |
| **Nikto** | L2 | GPL-2.0 | uid_nft (sep-proc) | worker | M | P3 |

Everything that actively injects (ZAP active, ffuf, dalfox, sqlmap) is L3+ and therefore already
requires a campaign and a human approval before it can touch a target. The governance is done; the
providers are not.

---

## 5. Catalogue — exploitation & credential (L4/L5, most-gated)

This exists in the capability model (`EXPLOIT_VALIDATION`, `DESTRUCTIVE`) and the gate already
demands a campaign plus an **independent** approver. But it is deliberately last, and some of it may
be a deliberate never.

| Tool | Level | Licence | Verdict |
|---|---|---|---|
| **Metasploit metadata** (existing — module→CVE map, reliability) | L0 | BSD-3 | in use, metadata only |
| **exploit existence/maturity** (Exploit-DB index, existing) | L0 | GPL-2.0 index | in use, no exploit bodies |
| **Metasploit module execution** | L4 | BSD-3 | P3 — campaign+approval; likely customer-hosted only |
| **nuclei with `-tags exploit` active templates** | L4 | MIT | P3 — governed |
| **credential spraying / testing** | L3 | own | P3 — approval, rate-limited, opt-in per account |
| **hashcat / john (offline cracking of provided hashes)** | L0 | MIT/own | P2 — offline, free host, but scope-of-use policy first |

Design principle already in the codebase: Guardian records that **an exploit exists and how reliable
it is** (to rank a finding) without **downloading or running** weaponized code. Storing exploit
bodies would make the knowledge base itself a liability. Moving from "an exploit exists" to "we ran
it" is a product-strategy decision, not just an engineering one, and this study flags it rather than
assuming it.

Interesting exception: **hashcat/john are offline** — cracking hashes the customer already holds is
L0 analytical work that runs on the free host. Valuable for password-audit engagements. Gated on a
usage policy (whose hashes, consent) rather than on infrastructure.

---

## 6. The AI dimension — honestly

The user asked for AI that can "search, think, and maybe invent a vulnerability that isn't already
in the AI." This deserves a straight answer, because over-promising here is how security products
lose trust.

### What is real and shippable now

1. **Triage & explanation.** Given a *real* finding from a *real* tool (a semgrep hit, a Zeek log, a
   YARA match, a CSPM misconfiguration), an LLM is excellent at: judging exploitability in context,
   writing the plain-language "why this matters," drafting remediation, and de-duplicating. This is
   the `AiAnalyst` that already exists — and its guardrails are already built and tested: it refuses
   to take severity from the model, scrubs secrets out of the prompt, neutralizes prompt-injection
   from scanned content, and records when the model contradicts a finding. **This is the P0 AI
   work: turn on the existing analyst** (needs `ANTHROPIC_API_KEY` — BLOCKER-3).

2. **Correlation across tools.** The best AI value is not one tool — it is reading *all* the
   evidence at once: "SAST found an unsanitized query, SCA found a vulnerable ORM version, DAST
   confirmed the endpoint is reachable — together this is an exploitable SQLi chain." An LLM
   reasoning over the combined evidence graph is genuinely more than the sum of the tools. This is
   the strongest differentiator and it is P1.

3. **Agentic investigation (bounded).** An LLM given a **restricted set of read-only tool calls**
   (run this specific query, fetch this specific evidence) can drive a triage loop: "the SAST hit is
   in `login()`, pull the callers, check whether the input is validated upstream." This is real and
   safe **only because the tool surface is the governed one** — the AI cannot invent a scan it is
   not authorized for; it calls the same policy-gated providers a human does. This is P2 and it is
   the honest version of "the AI thinks and searches."

### What is hype, and where the honesty line is

"The AI invents a novel vulnerability from nothing" — **no.** An LLM does not discover a zero-day by
introspection. What it *can* do, and what we should build toward without overselling:

- **Hypothesis generation, then tool verification.** The AI proposes *"this pattern looks like it
  could be an IDOR"* — and then a **real, governed tool** tests the hypothesis. The finding is only
  ever reported if a tool confirmed it. The AI narrows where to look; it never becomes the evidence.
  This keeps the product's core promise intact: **a finding is something a tool proved, never
  something a model asserted.** That is `engine_outcome()` extended to the AI — "the model thinks so"
  must never render as "it is real."

- **Variant analysis.** Given one confirmed bug, the AI is good at "where else does this exact
  pattern occur" — and each candidate is re-checked by the deterministic tool. This is a real force
  multiplier and it is intellectually honest.

The rule that keeps this from becoming snake oil: **the AI may direct the search and explain the
result, but a finding requires tool-produced evidence.** Any design that lets the model's opinion
become a customer-facing finding is rejected. The guardrails already in `guard.py` are the
enforcement point; the agentic layer extends them.

### AI integration mechanics

The seam exists: `services/ai_analyst` with a provider protocol and a Claude provider using the
official SDK, structured outputs, and refusal handling. Adding agentic tool-use means giving the
provider a **read-only, policy-gated** tool-call surface (the same `available_tool_providers()` the
worker uses, filtered to what the current principal is authorized for). The governance gate is
reused verbatim — the AI is just another principal, capped at whatever level the operator running it
holds. Model default is `claude-opus-5` per config; that is correct for this reasoning-heavy work.

---

## 7. Hard constraints (the things that actually limit us)

1. **The worker host (BLOCKER-1).** Everything in §4 and §5 needs a machine with `CAP_NET_ADMIN`.
   The current free Render host does not have it. Until it exists, active scanning is off — and that
   is correct, not broken. **§3 does not need it**, which is why the build starts there.
2. **Disk.** The free host has a small disk allowance. Memory-image forensics (Volatility), large
   PCAPs, and cartography's graph DB are disk-bound and are marked down accordingly.
3. **Licence.** The registry already blocks masscan, TruffleHog (AGPL), CodeQL (proprietary) and
   holds nmap for review. `tools/check_tool_licenses.py` enforces this in CI — **a tool not listed
   and APPROVED cannot enter an image.** Every new provider adds a registry row in the same commit.
4. **Credential custody.** Cloud posture and secret-verification tools hold customer credentials.
   The KMS-sealed path exists, but pointing it at a customer's cloud role is a trust decision that
   precedes the engineering.
5. **The AI key (BLOCKER-3).** The analyst is built and gated; it needs `ANTHROPIC_API_KEY`.
6. **`engine_outcome()` is non-negotiable.** Every tool added must report `not_checked` when it
   cannot run, and the AI must never turn an opinion into a finding. This is the product's whole
   credibility and it constrains every addition above.

---

## 8. Recommended build order

Sequenced so that everything early runs on the host we already have, and nothing is blocked waiting
on infrastructure that does not exist yet.

**Phase A — offline value on the current host (no new infra, no new blocker).**
`P0`: gitleaks · opengrep/bandit (SAST) · osv-scanner · checkov · YARA + file-magic + hashing
(forensics) · turn on the AI analyst (needs the key). These are all L0, all licence-clean, all
free-host, and each is an S/M provider against a seam that already exists.

**Phase B — offline forensics & PCAP depth.**
`P1`: tshark/Zeek PCAP dissection (the Wireshark ask) · PE/ELF analysis · detect-secrets · syft +
grype · KICS/tfsec. Plus the **AI correlation layer** (§6.2) — the real differentiator.

**Phase C — cloud posture (credential review first).**
`P1/P2`: Prowler · Kubescape · kube-bench · PMapper. Precondition: the customer-cloud-credential
trust decision.

**Phase D — active network (requires the worker host; unblock BLOCKER-1 first).**
`P1`: naabu + fingerprintx + subfinder + dnsx + httpx. This is the moment the worker host must
exist. Do not start it before that.

**Phase E — active web/API (needs host + campaign/approval already built).**
`P2`: ZAP · ffuf · dalfox · Schemathesis. Plus **agentic AI investigation** (§6.3) over the governed
tool surface.

**Phase F — exploitation & credential (most-gated; some may be deliberate never / customer-hosted).**
`P3`: governed nuclei-exploit · Metasploit execution · credential testing. Plus offline hashcat/john
(P2, free host, usage policy first).

---

## 9. What "start" means

When the word is *go*, the first provider is **gitleaks**: L0, MIT, offline, free-host, already in
the licence registry, and it fills an engine (`SecretsEngine`) that already exists. It is the
smallest complete instance of the whole seam — write the class, declare capabilities, register the
entry point, add tests, done — and it proves the method end to end on the deployed host before
anything heavier is attempted.

Each subsequent provider is the same shape. The framework is built. This is filling it in.
