#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

go_cache="${GOCACHE:-$(go env GOCACHE)}"
go_mod_cache="${GOMODCACHE:-$(go env GOMODCACHE)}"
go_path="${GOPATH:-$(go env GOPATH)}"
sandbox="$(mktemp -d "${TMPDIR:-/tmp}/packy-delivery-validation.XXXXXX")"
cleanup() { rm -rf "$sandbox"; }
trap cleanup EXIT

export HOME="$sandbox/home"
export XDG_CONFIG_HOME="$sandbox/xdg"
export GOCACHE="$go_cache"
export GOMODCACHE="$go_mod_cache"
export GOPATH="$go_path"
mkdir -p "$HOME" "$XDG_CONFIG_HOME"

unformatted="$(gofmt -l cmd internal)"
if [[ -n "$unformatted" ]]; then
  echo "Go files require formatting:" >&2
  echo "$unformatted" >&2
  exit 1
fi

go vet ./...
go test ./...
./scripts/test-release-tools.sh
