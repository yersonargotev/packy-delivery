# ADR 0001: Own Packy issue delivery independently

## Status

Accepted.

## Context

Packy's issue-delivery system is a maintenance product with its own evidence
schemas, resumable lifecycle, Git and GitHub effects, review policy,
persistence, recovery, and operator-facing skill. The distributed Packy product
is an installer and configurator and does not expose or import that system.

Keeping both in one repository coupled unrelated domains, validation surfaces,
release concerns, and reasons to change.

## Decision

This repository owns the Packy-specific issue-delivery system:

- `internal/deliveryevidence` owns canonical evidence schemas and validation;
- `internal/issuedelivery` owns the resumable `Advance` lifecycle;
- `cmd/packy-deliver` owns Packy-specific Git, GitHub, validation, review, and
  cleanup adapters;
- `workflows/packy-issue-delivery.md` is the behavioral contract;
- `.agents/skills/deliver-packy-issue` is the thin model-facing adapter.

The project remains specific to `yersonargotev/packy`. It consumes Packy only
through observable repository boundaries such as Git, GitHub, issues, required
checks, and `scripts/validate-packy.sh`. It must not import Packy's internal Go
packages.

Existing CLI semantics, JSON contracts, schema v1/v2 records, and state beneath
the target repository's Git common directory remain compatible with the
pre-extraction implementation.

## Consequences

- Packy and Packy Delivery can evolve and release independently.
- A delivery run persists with the target Packy repository and can resume after
  upgrading or relocating this executable.
- Compatibility is tested at command, schema, filesystem, validation, and
  GitHub boundaries rather than through shared source packages.
- Cross-repository generalization is deferred until demonstrated by a real
  consumer.
