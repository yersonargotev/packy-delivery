#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 --version VERSION --checksums PATH --out PATH" >&2
  exit 2
}

version=""
checksums=""
out=""
while (($# > 0)); do
  case "$1" in
    --version)
      (($# >= 2)) || usage
      version="$2"
      shift 2
      ;;
    --checksums)
      (($# >= 2)) || usage
      checksums="$2"
      shift 2
      ;;
    --out)
      (($# >= 2)) || usage
      out="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "version must be a stable semantic version without a v prefix" >&2
  exit 1
}
[[ -f "$checksums" && -n "$out" ]] || usage

checksum_for() {
  local artifact="$1"
  local checksum
  checksum="$(awk -v artifact="$artifact" '$2 == artifact { print $1 }' "$checksums")"
  [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || {
    echo "missing or invalid checksum for $artifact" >&2
    exit 1
  }
  printf '%s' "$checksum"
}

darwin_arm64="packy-deliver_v${version}_darwin_arm64"
darwin_amd64="packy-deliver_v${version}_darwin_amd64"
linux_arm64="packy-deliver_v${version}_linux_arm64"
linux_amd64="packy-deliver_v${version}_linux_amd64"

mkdir -p "$(dirname "$out")"
{
  cat <<EOF
class PackyDelivery < Formula
  desc "Resumable issue-delivery orchestrator for Packy"
  homepage "https://github.com/yersonargotev/packy-delivery"
  version "$version"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yersonargotev/packy-delivery/releases/download/v$version/$darwin_arm64", using: :nounzip
      sha256 "$(checksum_for "$darwin_arm64")"
    else
      url "https://github.com/yersonargotev/packy-delivery/releases/download/v$version/$darwin_amd64", using: :nounzip
      sha256 "$(checksum_for "$darwin_amd64")"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yersonargotev/packy-delivery/releases/download/v$version/$linux_arm64", using: :nounzip
      sha256 "$(checksum_for "$linux_arm64")"
    else
      url "https://github.com/yersonargotev/packy-delivery/releases/download/v$version/$linux_amd64", using: :nounzip
      sha256 "$(checksum_for "$linux_amd64")"
    end
  end

  def install
    downloaded_binary = Dir["packy-deliver_*"].first
    odie "downloaded packy-deliver binary not found" if downloaded_binary.nil?
    bin.install downloaded_binary => "packy-deliver"
  end

  test do
    assert_equal "#{version}\n", shell_output("#{bin}/packy-deliver version")
  end
end
EOF
} >"$out"
