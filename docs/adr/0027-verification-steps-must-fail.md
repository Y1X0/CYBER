# ADR-027 — A verification step must be able to fail

- **Status:** Accepted
- **Date:** 2026-08-23
- **Deciders:** CTO, Platform Engineering

## Context

On 23 August 2026 the deployed Guardian went from executing nothing to running a customer journey
end to end — 21 PASS, 0 FAIL. Five blockers were cleared to get there. Four of the five were found
late, and the reason each one hid is the same reason: **a step reported success without having
established anything.**

The cost was not the bugs. Each was small. The cost was that every one of them was wearing a green
tick, so the search kept starting from a false premise. Roughly five hours of the day went into
diagnosis that a step failing honestly would have made unnecessary.

The four precedents, all recorded with run IDs in `docs/BUILD_STATUS.md`:

1. **`alembic upgrade head` inside an image without the migrations.** `guardian-cutover.yml` runs
   alembic *inside the pinned image*, and the pin was four days stale. That image's migration
   directory stopped at `0011`, so alembic would have found head `0011`, agreed the database was up
   to date, and exited 0. A green migrate step over a schema that never moved. Caught by comparing
   the image's build commit against the migration file dates — not by the step.

2. **`pipefail` + `grep -q` discarding a successful ping.** The worker liveness gate ran
   `celery … inspect ping … 2>/dev/null | grep -q pong` under `set -uo pipefail`. `grep -q` exits on
   first match and closes the pipe; celery dies of `SIGPIPE` and exits non-zero; `pipefail` adopts
   that status. The gate reported failure **after `pong` had already been printed**, and
   `2>/dev/null` threw away the evidence. Run 32621666688 was discarded on that basis and the first
   diagnosis blamed the broker's remote-control channel — infrastructure that was working fine.

3. **`guardian-deploy.yml` succeeding without deploying.** The step updated the Render service's
   `imagePath` and exited 0 in two seconds. It never checked that a deploy was created, and Render's
   `autoDeployTrigger` is `commit`, which never fires for an image-backed service. The service
   config pointed at the new digest while the old container kept serving. `HEALTH_PATH` was defined
   in the workflow's `env:` and never used by anything.

4. **`step=verify` that does not exist.** `guardian-cutover.yml` offers `verify` in its `step` input
   and implements no matching step. Selecting it runs nothing and reports success. The
   post-migration check had to be done with the backup drill instead, because the workflow's own
   verify option would have "confirmed" the migration by doing nothing at all.

Every one of these is the same shape. A tick that means "this step ran" was read as "this thing is
true".

## Decision

**A step whose purpose is to verify must have a reachable failure path, and that path must be
exercised or argued for before the step is trusted.**

Concretely, for any verification, gate, health check, or preflight added to this repository:

1. **State what would make it fail.** If the answer is "nothing I can think of", it is not a
   verification. Delete it or give it teeth. A step that cannot fail is a ritual: it costs time,
   occupies the place where a check belongs, and pays nothing.

2. **Verify the thing, not a proxy for it.** Prefer the most direct observation available. The
   migration was confirmed by reading `alembic_version` out of the database, not by the migrate
   step's exit code. Worker liveness is gated on the worker's own `ready.` line — the same channel
   that carries the work — rather than on remote control, which travels a different path and can be
   down while the worker consumes normally.

3. **A gate must be weaker than what it guards.** Precedent 2 in full: the gate demanded a working
   pidbox to permit a journey that does not need one. A gate stricter than the thing behind it will
   eventually reject a healthy system, and it costs a whole run to learn that. When in doubt, let
   the expensive thing run and report the weaker signal as a warning.

4. **Never discard the diagnosis.** No `2>/dev/null`, no swallowed stderr, no truncated error in a
   step whose job is to explain a failure. Precedent 2 cost an extra run purely because the reason
   was thrown away.

5. **Silence is not success.** If a step that changes production prints nothing, that is a fact
   needing an explanation before it is read as "clean". The migrate step printed nothing because
   `alembic.ini` sets `logger_alembic` to `INFO` with empty `handlers`, so records propagate to a
   root logger at `WARNING` and vanish. That explanation was found *after* the result was confirmed
   independently, in that order deliberately.

6. **A named option must do the named thing.** An input value that maps to no implementation is
   worse than a missing feature, because it answers the question it was asked.

## Consequences

**Accepted cost.** Verification steps get longer and slower. A probe that opens a connection costs
seconds that a `[ -n "$VAR" ]` does not. That is the trade being made deliberately: the connectivity
probe added to `guardian-golden-run.yml` turned "the worker took the scan and never finished" —
indistinguishable from the A1 blocker — into a named unreachable host in five seconds.

**Applies to.** CI steps, deployment workflows, preflights, health checks, readiness gates, and any
tool whose output is used as evidence in `BUILD_STATUS.md`. It does not apply to steps that only
*do* work; a build step is allowed to simply build.

**Open items already under this rule** — these are one decision with four instances, not four
unrelated chores:

| Item | Failure it cannot currently report |
|---|---|
| `guardian-cutover.yml` `step=verify` | anything at all — no implementation exists |
| `guardian-deploy.yml` | the deploy did not roll out; the service still serves the old image |
| `infra/docker/Dockerfile.scanner` | base-image CVEs with published fixes (no `apt-get upgrade`; the API image had the same gap and it took a blocked release to surface it) |
| `tools/guardian_preflight.py` docstring | it names a digest that is no longer production, so an operator following it verifies the wrong image |

**Relationship to the safety property.** This is the operational form of what `engine_outcome()`
already does for scan results. An engine that could not examine something reports `not_checked`
rather than silently implying `resolved` — the three-state outcome exists precisely so that "I did
not look" is never rendered as "it is fine". Run 32624227051 confirmed that live, with
`not_checked=4` on a retest. A CI step reporting success without having checked is the same
false-clean, one layer out, and deserves the same treatment.
