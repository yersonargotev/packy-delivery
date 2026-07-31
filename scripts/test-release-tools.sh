#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sandbox="$(mktemp -d "${TMPDIR:-/tmp}/packy-delivery-release-test.XXXXXX")"
cleanup() { rm -rf "$sandbox"; }
trap cleanup EXIT

contract_version="$(
  sed -nE 's/^Release: v([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' \
    "$root/workflows/packy-issue-delivery.md"
)"
skill_version="$(
  sed -nE 's/^Compatible release: v([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' \
    "$root/.agents/skills/deliver-packy-issue/SKILL.md"
)"
[[ -n "$contract_version" && "$contract_version" == "$skill_version" ]]
grep -F 'packy-deliver version' "$root/.agents/skills/deliver-packy-issue/SKILL.md" >/dev/null
grep -F 'qualification is approved; awaiting candidate development' \
  "$root/.agents/skills/deliver-packy-issue/SKILL.md" >/dev/null
grep -F 'Except for the recognized candidate-development handoff above' \
  "$root/.agents/skills/deliver-packy-issue/SKILL.md" >/dev/null
grep -F 'packy-deliver workspace prepare' \
  "$root/.agents/skills/deliver-packy-issue/SKILL.md" >/dev/null
grep -F 'one-proof-per-criterion order' \
  "$root/.agents/skills/deliver-packy-issue/SKILL.md" >/dev/null
grep -F 'bounded active-operation object' \
  "$root/.agents/skills/deliver-packy-issue/SKILL.md" >/dev/null

version="1.2.3"
checksums="$sandbox/SHA256SUMS"
formula="$sandbox/packy-delivery.rb"
for platform in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
  artifact="packy-deliver_v${version}_${platform}"
  printf '%064d  %s\n' 0 "$artifact" >>"$checksums"
done

"$root/scripts/generate-homebrew-formula.sh" \
  --version "$version" \
  --checksums "$checksums" \
  --out "$formula"

grep -F 'version "1.2.3"' "$formula" >/dev/null
grep -F 'license "MIT"' "$formula" >/dev/null
grep -F 'bin.install downloaded_binary => "packy-deliver"' "$formula" >/dev/null
grep -F 'packy-deliver version' "$formula" >/dev/null

if "$root/scripts/generate-homebrew-formula.sh" \
  --version "v1.2.3" \
  --checksums "$checksums" \
  --out "$sandbox/invalid.rb" 2>/dev/null; then
  echo "formula generator accepted a prefixed version" >&2
  exit 1
fi
