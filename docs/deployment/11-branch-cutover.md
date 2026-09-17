# Deployment branch cutover: `claude/…` → `main`

## Where we are

The pilot control plane deploys from the feature branch
`claude/security-guardian-architecture-p1315d`, not `main`:

- `render.yaml` pins `services[0].branch` to that branch, with
  `autoDeployTrigger: commit`, so every push to it redeploys the Render web service.
- The scanner image is built and repinned from the same branch
  (`guardian-deploy-worker.yml` / `guardian-burst-worker.yml`).

This was correct while the hardening work landed on the branch and `main` had not yet caught up.
It is **not** where a real deployment should sit: `main` is the branch a team reviews, protects, and
reasons about, and deploying from a long-lived feature branch means production tracks unreviewed
history.

## The plan

Deploy from `main` once the branch is merged:

1. **Merge** `claude/security-guardian-architecture-p1315d` into `main` via a reviewed pull request
   (do not fast-forward-push the branch onto `main`; the review is the point).
2. **Repoint Render** — set `services[0].branch: main` in `render.yaml` (and, if the service was
   created before this change, update the branch in the Render dashboard so the blueprint and the
   live service agree). Autodeploy then tracks `main`.
3. **Repoint the image pipeline** — the deploy/burst workflows already run on whatever ref triggers
   them; run them from `main` after the merge so the next scanner image is built from `main` and the
   burst worker is repinned to that digest.
4. **Protect `main`** — require the PR review + the CI checks (`pytest`, `ruff`, `pip-audit`) before
   merge, so what deploys is always what passed review.

## Keep-alive

`guardian-keepalive.yml` pinged `/health` every 10 minutes to keep the free Render instance warm.
Its schedule is now **disabled** (it runs on `workflow_dispatch` only). Revisit the keep-alive with
the target plan at cutover:

- **Paid, always-on instance** → no keep-alive needed; leave the cron disabled.
- **Free instance** → re-enable the cron by restoring the `schedule:` block in
  `guardian-keepalive.yml` (it warms the instance so the first real request does not cold-start).

Until the cutover, warm the instance on demand by running the Keep-Alive workflow from the Actions
tab.
