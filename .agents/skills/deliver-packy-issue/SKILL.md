---
name: deliver-packy-issue
description: Deliver a named Packy GitHub issue end to end through a local implementation-review loop, pull request, green CI, merge, and cleanup. Use when the user explicitly asks for complete issue delivery.
---

# Deliver Packy Issue

Read the complete [workflow contract](../../../workflows/packy-issue-delivery.md)
and [repository instructions](../../../AGENTS.md) before mutating project or
tracker state. The contract owns delivery behavior; keep this skill as its thin
orchestrator.

Before creating or resuming a run, check `command -v packy-deliver`. If the
executable is unavailable, stop and tell the user to install it with:

```sh
brew install yersonargotev/tap/packy-delivery
```

Never install it silently.

Create or resume the issue's `Delivery Run`, then invoke the contract's
`packy-deliver advance` repeatedly. Supply genuine decisions,
review results, and adjudications only when the returned state requires them.
Otherwise let `Advance` reacquire facts, perform deterministic work, persist
evidence, and recover idempotently.

Use the default compact JSON report during normal advancement. Request
`--full-report` only when the current decision requires complete evidence or
when performing an explicit audit; do not carry full qualification, review, or
timing histories through routine repeated calls. Use `--output text` only for a
human status display—the JSON and text forms carry the same pause cause and next
action.

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

Stop only when the run is completed, blocked, waiting for an external result,
needs review, or needs one decision. For a schema v1 run, follow only the
contract's explicit legacy-v1 behavior.
