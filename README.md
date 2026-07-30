# Packy Delivery

Packy Delivery is the standalone issue-delivery orchestrator for Packy. It
preserves the `Delivery Run`, evidence, qualification, review, validation,
non-local delivery, recovery, and cleanup contracts from Packy while exposing
them through the `packy-deliver` executable.

## Build and test

Requires Go 1.23 or newer.

```sh
./scripts/validate-packy-delivery.sh
go build ./cmd/packy-deliver
```

Install the executable with:

```sh
go install github.com/yersonargotev/packy-delivery/cmd/packy-deliver@latest
```

## Use

Start or resume delivery of one Packy issue:

```sh
packy-deliver advance \
  --repository /absolute/path/to/packy \
  --issue N \
  --risk-profile low-risk|standard|high-risk
```

The command can perform Git and GitHub delivery effects after local readiness
and explicit non-local authorization. Use a sandboxed `HOME` and
`XDG_CONFIG_HOME` for local checks that resolve or write user paths. See
[the issue-delivery workflow](workflows/packy-issue-delivery.md) for the full
behavioral contract.

The project is intentionally specific to
[`yersonargotev/packy`](https://github.com/yersonargotev/packy). It observes the
target repository through Git, GitHub, its required checks, and
`scripts/validate-packy.sh`; it does not import Packy's internal Go packages.

Historical schema-v1 commands remain available under:

```sh
packy-deliver legacy-v1 <historical-subcommand> ...
```
