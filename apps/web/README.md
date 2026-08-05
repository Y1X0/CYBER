# Security Guardian — Web Dashboard

React + TypeScript + Vite SPA for the customer security dashboard (Phase 3).

## What it shows

- **Security score** (0–100, deterministic) + severity mix + recent scans
- **Findings** per scan (severity, risk score, standards)
- **AI chat** grounded strictly on the customer's own findings
- Points to the **PDF report export** endpoint

## Run

```bash
npm install
npm run dev        # http://localhost:5173 — proxies /api → http://localhost:8000
```

Sign in with the bootstrap admin from `make seed` (default `admin@example.com` / `ChangeMe123!`).

## API surface used

`POST /api/v1/auth/login` · `GET /api/v1/dashboard` · `GET /api/v1/findings?scan_id=` ·
`POST /api/v1/chat` · `GET /api/v1/reports/{id}/export?format=pdf`

> Phase 3 scaffold: intentionally dependency-light (no state library / component kit) so the
> integration with the control plane is easy to read. Not built in the Python CI.
