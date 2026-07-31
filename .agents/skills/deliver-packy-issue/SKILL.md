---
name: deliver-packy-issue
description: Deliver a named Packy GitHub issue end to end through a local implementation-review loop, pull request, green CI, merge, and cleanup. Use when the user explicitly asks for complete issue delivery.
---

# Deliver Packy Issue

Compatible release: v0.5.0

Read the complete [workflow contract](../../../workflows/packy-issue-delivery.md)
and [repository instructions](../../../AGENTS.md) before mutating project or
tracker state. The contract owns delivery behavior; keep this skill as its thin
orchestrator.

Before creating or resuming a run, enforce the release preflight:

1. Check `command -v packy-deliver`. If the executable is unavailable, stop and
   tell the user to install it with:

```sh
brew install yersonargotev/tap/packy-delivery
```

2. Derive the expected CLI version by removing the leading `v` from the
   `Compatible release` declared above. Run `packy-deliver version` and require
   that exact value.
3. If the installed version differs, stop before invoking `advance` and report
   both expected and observed versions. For a Homebrew installation, tell the
   user to run:

```sh
brew update
brew upgrade packy-delivery
```

Never install or upgrade it silently. Never combine a mismatched executable,
contract, and skill against an existing Delivery Run.

After the version preflight, use `packy-deliver help` and
`packy-deliver help advance` as the executable authority for current command
and option syntax. Do not infer syntax from source searches or historical
invocations.

When the operator's Packy checkout must remain untouched or cannot satisfy the
clean attached-branch invariant, use `packy-deliver help workspace` and prepare
a new integration workspace with `packy-deliver workspace prepare`. Supply the
exact source checkout, issue, branch kind, and a new absolute destination
outside the source repository and all of its worktrees. Continue the Delivery
Run from the prepared destination. Never clean, stash, reset, adopt, or mark the
source checkout as delivery-owned; workspace preparation performs no fetch or
GitHub mutation and grants no non-local authorization.

Create or resume the issue's `Delivery Run`, then invoke the contract's
`packy-deliver advance` repeatedly. Supply genuine decisions,
review results, and adjudications only when the returned state requires them.
Otherwise let `Advance` reacquire facts, perform deterministic work, persist
evidence, and recover idempotently.

Use this schema-v2 operating loop:

1. Inspect with `packy-deliver status --repository ... --issue ...` when a
   compact current projection is sufficient.
2. Invoke `advance` only when its typed `next_action` requires Advance.
3. For a semantic-input pause, invoke `input-template` with the exact pending
   kind and a sandboxed output path. Replace only the explicit judgment
   placeholders, then pass that same file unchanged to its matching `advance`
   option.
4. For an independent-review pause, invoke `review-packets` with the exact kind,
   axis, or boundary requested. Send immutable packets to independent reviewers
   in parallel where allowed. Fill their separate response templates and pass
   the individual response files or packet directory unchanged through repeated
   `--review-content`; never construct a parallel review envelope. In a Spec
   candidate response, preserve every prefilled identity and the generated
   one-proof-per-criterion order; replace only the seven semantic evidence
   placeholders for each proof.
5. For `external-result` or `lock-contention`, invoke bounded `watch` with an
   explicit interval and timeout. When it reports an actionable change, invoke
   `advance` so the engine—not this skill—adopts the result. During lock
   contention, treat the bounded active-operation object returned by `status`
   or `watch` as the only operational evidence. Never inspect its private
   sidecar, infer failure from elapsed time, or terminate the owning process.

Never inspect or derive a private delivery-state path. Never select an internal
phase, invent semantic input, translate generated JSON into another shape,
adopt an external result outside `Advance`, or treat timing objectives as
readiness or correctness gates.

One CLI invocation already converges consecutive safe deterministic
transitions. Do not repeat a typed decision, repair, review, correction, CI
attribution, or authorization merely because several internal transitions
completed before the returned genuine pause.

Use the default compact JSON report during normal advancement. Request
`--full-report` only when the current decision requires complete evidence or
when performing an explicit audit; do not carry full qualification, review, or
timing histories through routine repeated calls. Use `--output text` only for a
human status display—the JSON and text forms carry the same pause cause and next
action.

Treat `--decision`, `--repair`, `--review-content`, and `--ci-attribution` as
paths to files containing exactly one typed JSON value. Bind the content to the
exact pending request or observed CI identity returned by `Advance`; never pass
inline JSON or free-form prose and never invent or replay a stale identity.

When `Advance` returns `provide-qualification-correction`, submit one complete
correction that echoes the returned request ID, authority hash, reviewed matrix
hash, and full finding-ID set. Preserve every criterion identity and authority
text, replace every compiler marker and placeholder with a criterion-specific
evidence plan, and include concrete correction evidence. Do not ask an
independent reviewer to restate compiler-known findings and do not fabricate a
`QualificationReview`; independent qualification review begins only after the
corrected run returns to `needs-review`.

Use the compiler correction binding grammar exactly:

- correction evidence is exactly
  `[request:<request-id>] findings=<canonical-comma-joined-finding-ids>; rationale=<rationale>`;
- every owning-seam and evidence cell is exactly
  `[criterion:<criterion-id>] source=<kind>:<locator>; assertion=<assertion>`.

Use only `file`, `symbol`, `test`, `command`, `fixture`, `review`, `authority`,
or `not-applicable` source kinds and a concrete locator shaped for that kind.
Use the exact returned canonical finding list. Rationale and assertion text
must be bounded, marker-free statements; do not add, omit, reorder, or duplicate
fields.

When `Advance` returns `state: waiting`, reason
`qualification is approved; awaiting candidate development`, pause cause
`external-result`, next action `observe-external-result`, and no candidate,
treat it as the local development handoff rather than a generic external wait.
Implement the approved issue in the target checkout, run focused verification,
and invoke the same `advance` command again. Do not create candidate, risk, or
validation receipts yourself; `Advance` observes the changed Git HEAD and
persists them.

Except for the recognized candidate-development handoff above, stop only when
the run is completed, blocked, waiting for an external result, needs review, or
needs one decision. For a schema v1 run, follow only the contract's explicit
legacy-v1 behavior.
