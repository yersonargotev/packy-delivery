# ADR 0002: Distinguish Advance caller windows from process cancellation

## Status

Accepted

## Context

An `Advance` invocation holds the issue lock while it runs validation. A caller
can stop waiting for that invocation without terminating the command process,
or the invocation's context can actually be cancelled, or validation can finish
normally. Those events have different lifecycle consequences and previously
lacked a deterministic process-level reproduction.

The reproduction in `cmd/packy-deliver/advance_process_test.go` runs the public
command parser and a real `issuedelivery.Module.Advance` in a separate process.
That operation holds its real Git-common-directory issue flock and executes the
production validation-session and validator adapters in a temporary Git
repository. Explicit filesystem signals record validator start, release,
cancellation, exit, and lock release. Concurrent public `status` and `watch`
processes observe contention, and `watch` observes the transition back to
availability. The detached-caller scenario puts the process wait behind a real
bounded caller window, lets that window expire without signalling the command,
and then proves that both command and validator remain alive. The test sandboxes
user and configuration roots and installs a failing `gh` guard, proving that
lock contention returns before any GitHub observation or effect.

The reproduction establishes:

| Scenario | Validator | Issue lock | Concurrent observation |
| --- | --- | --- | --- |
| Caller stops waiting, command remains alive | remains alive until explicitly released | remains held | contention persists, then becomes available after release |
| Invocation context is cancelled | direct owned validator is terminated and reaped | released after validator exit | contention becomes availability |
| Validator completes normally | exits after explicit release | released after validator exit | contention becomes availability |

The production executable currently starts commands with
`context.Background()`. It therefore does not yet translate process signals
into the actual invocation-context cancellation exercised by the reproduction.

## Decision

The implementation ticket for long-running operation observability and
cancellation must implement this contract:

- Each live command invocation has a stable operation identity that is distinct
  from the resumable Delivery Run identity. Retries are new operations even
  when they resume the same run.
- The operation is created before attempting the issue lock and exposes only
  bounded operational metadata: operation identity, command kind, current
  phase, start time, and a relevant persisted validation-session identity when
  one exists. Raw logs do not become canonical run evidence.
- Progress changes are monotonic within one operation. `status` and `watch`
  report the same stable identity and latest bounded phase while the operation
  is alive; lock-contention responses retain `retry-advance` semantics.
- Expiry or cancellation of an external caller's waiting window does not imply
  cancellation of an `Advance` process. While that process is intentionally
  alive, its operation remains observable and it may retain the issue lock.
- Actual command cancellation must be explicit. The executable must derive a
  cancellable command context from its supported termination signals and pass
  that context through `Advance` and every owned subprocess.
- Cancellation must terminate and reap all subprocesses owned by the operation,
  not only return control to the caller. No owned process may survive the
  operation unexpectedly.
- The issue lock is released only after owned subprocess termination has been
  observed and the operation has reached a terminal cancelled, failed, or
  completed state. Lock availability remains an independent observable fact.
- Normal completion records terminal progress and releases the issue lock after
  the validator exits. Cancellation never produces a successful validation
  receipt.
- Reobservation after any long operation remains authoritative. Operational
  metadata does not replace persisted Delivery Run evidence or weaken existing
  Git, authority, validation, or non-local gates.

## Consequences

- A client-side timeout and an operation cancellation cannot be inferred from
  one another; callers and operators must be able to tell which occurred.
- The follow-up implementation needs signal-derived command contexts and
  operation metadata visible to `status` and `watch`.
- Subprocess ownership needs an explicit whole-operation policy. The current
  direct `exec.CommandContext` child is cancelled and reaped by the reproduced
  context path, but the implementation must also prevent descendants from
  surviving.
- Existing command JSON, schema v1/v2 records, Delivery Run identity, and state
  beneath the Git common directory remain compatible.
