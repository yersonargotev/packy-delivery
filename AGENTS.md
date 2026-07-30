# Agent guidance

- Read `docs/adr/0001-extract-packy-delivery.md` and the issue-delivery workflow
  before changing architecture or delivery behavior.
- Keep resumable delivery behavior in `internal/issuedelivery`; keep
  `cmd/packy-deliver` as the Packy-specific executable adapter.
- Preserve command semantics, canonical JSON, schema v1/v2 compatibility, and
  Git-common-directory state paths unless an accepted migration explicitly
  changes them.
- Do not generalize beyond Packy without a proven second consumer and an
  accepted architectural decision.
- Sandbox `HOME` and `XDG_CONFIG_HOME` for tests or manual checks. Never invoke
  non-local Git or GitHub effects during validation.
- Run `./scripts/validate-packy-delivery.sh` before committing or reporting
  success.
