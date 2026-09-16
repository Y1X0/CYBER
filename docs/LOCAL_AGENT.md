# Local agent — Home Network & Server posture

**Status: IMPLEMENTED (assessment engine + allowlisted ingestion + reference collector). The agent
is the REQUIRED DEPLOYMENT MODE — a cloud server cannot and must not scan a private LAN or an
authenticated host directly.**

## Why an agent (not cloud-to-LAN scanning)

Guardian runs in the cloud. It has no route to your home network's `192.168.x.x` devices or into
your server's authenticated OS state, and it must never pretend otherwise. So posture is collected
**where you are** by an agent you install and authorize, and Guardian assesses the submitted report.
This keeps the platform's security model intact: authorized, scoped, auditable, non-destructive.

## The security contract (enforced)

- **Allowlisted only.** `guardian_scanner.hostposture.schema.normalize` reads only the known posture
  fields and **drops everything else** — a stray token or file content the agent might include never
  enters storage. String values are scrubbed for credential shapes as defence in depth.
- **Authorization required.** The report must assert `"authorized": true`; the engine
  (`HostPostureEngine`) **refuses to assess** a report without it. The reference agent refuses to run
  without `--authorized`.
- **Read-only / non-destructive.** The reference collector reads OS state only (listening sockets via
  `ss`, the neighbour/ARP table the OS already has, `sshd_config`, `os-release`, firewall status,
  `docker version`). **No** active LAN sweeping, port flooding, credential attacks, Wi-Fi attacks,
  deauth, packet injection, or exploitation — ever.

## Flow

1. Run the reference agent on your host / a machine on your home network:
   ```
   python3 agents/guardian_agent.py --mode server  --authorized > posture.json   # Linux server
   python3 agents/guardian_agent.py --mode network --authorized > posture.json   # home network
   ```
2. Create an asset of kind `server_host` or `network_host`.
3. Create a scan requesting `engines: ["host_posture"]`, submitting `posture.json` as the scan's
   inline content (or the asset config `posture`).
4. Findings appear in the normal pipeline — risk score, evidence, AI analyst, report, audit.

## What is assessed

**`network_host` (home router / devices)** — router management over cleartext HTTP (CWE-319),
management exposed to the WAN (CWE-284, CRITICAL), UPnP enabled (CWE-284), insecure/legacy services
on LAN hosts (telnet/ftp/rsh, CWE-319).

**`server_host` (Linux)** — SSH `PermitRootLogin` (CWE-250) and `PasswordAuthentication` (CWE-262)
and protocol 1 (CWE-327); host firewall disabled (CWE-1188); end-of-life OS (CWE-1104);
insecure/legacy listening services (CWE-319); passwordless sudo (CWE-250); Docker daemon exposed over
TCP (CWE-284, CRITICAL); privileged containers (CWE-250).

## Report schema (the allowlist)

```jsonc
{
  "kind": "server_host" | "network_host",
  "authorized": true,
  "hostname": "...", "collected_at": "ISO-8601",
  "network": {                                 // network_host
    "gateway": "192.168.1.1",
    "router": {"vendor","model","firmware","mgmt_http","mgmt_https","wan_mgmt","upnp"},
    "hosts": [{"ip","mac","vendor","hostname","open_ports":[{"port","service","tls","protocol"}]}]
  },
  "server": {                                  // server_host
    "os": {"distro","version","kernel","eol"},
    "listening": [{"port","service","address","protocol"}],
    "firewall": {"enabled": true|false},
    "ssh": {"exposed","permit_root_login","password_authentication","protocol"},
    "users": {"passwordless_sudo": bool, "privileged": ["..."]},
    "packages": [{"name","version"}],
    "docker": {"installed","daemon_tcp","privileged_containers"}
  }
}
```

## Known limitations / future work

- **Router deep identification** (vendor/model/firmware) and Wi-Fi config are collected by the agent
  where the OS/router exposes them safely; the reference agent leaves these fields for a
  router-specific collector. **No** credential access to the router is performed.
- **Server package → CVE matching** reuses the platform's SCA/vuln-intel when the agent submits a
  package inventory; the reference agent ships an empty `packages` list by default (opt-in) to avoid
  sending an inventory without explicit consent.
- The reference agent is a **starting point**; a production agent adds an authenticated submission
  channel. The security contract (allowlisted, read-only, authorized) is the part that must not
  change.
