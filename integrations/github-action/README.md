# Security Guardian — GitHub Action

Run a Security Guardian scan in CI and **block the build** when the deployment gate fails
(critical findings, KEV matches, high + high-EPSS, etc. — per your policy).

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
jobs:
  guardian:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/security-guardian/integrations/github-action@main
        with:
          asset-id: ${{ vars.GUARDIAN_ASSET_ID }}
          api-url: ${{ vars.GUARDIAN_API_URL }}
          token: ${{ secrets.GUARDIAN_TOKEN }}   # never hardcode
          engines: "secrets,sast,sca"
```

The step exits non-zero when the gate is not passed, failing the job.

Equivalent CLI (any CI system):

```bash
GUARDIAN_API_URL=https://guardian.example.com GUARDIAN_TOKEN=*** \
  guardian scan --asset "$ASSET_ID" --engines secrets,sast,sca
```

Alternatively, wire the **webhook** (`POST /webhooks/github`, HMAC-verified) so a push auto-triggers
a scan for the mapped repo asset with no workflow changes.
