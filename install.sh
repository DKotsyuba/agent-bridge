#!/usr/bin/env bash
# Agent Bridge local-bundle installer (bridge-bundle-v1). No download, no
# archive extraction. The bundle comes from `cargo xtask package`, which
# prints the SHA256SUMS digest; pass that digest out of band. The bundle is
# first copied into a private temporary directory and everything below is
# checked and executed from that copy, so a bundle that changes afterwards
# cannot change what runs. Nothing from the copy is executed until SHA256SUMS
# matches the digest and every expected file matches SHA256SUMS; the verified
# `bridge` then re-verifies and seals the bundle against the same digest. A
# hash is not a signature: trust is the operator's own local build. Writes
# only under --home and --bin-dir (and the removed temporary copy).
set +x
set -euo pipefail
umask 077
bundle=''
sums=''
home=${AGENT_BRIDGE_HOME:-"$HOME/.agent-bridge"}
bin_dir="$HOME/.local/bin"
usage='install.sh --bundle ABS_DIR --sums-sha256 HEX [--home ABS_PATH] [--bin-dir ABS_PATH]'
while (($#)); do
  case "$1" in
    --help) echo "$usage"; exit 0;;
    --bundle|--sums-sha256|--home|--bin-dir)
      (($# >= 2)) || { echo 'Missing option value' >&2; exit 2; }
      case "$1" in --bundle) bundle=$2;; --sums-sha256) sums=$2;; --home) home=$2;; --bin-dir) bin_dir=$2;; esac
      shift 2;;
    *) echo "Unknown option; $usage" >&2; exit 2;;
  esac
done
[[ "$sums" =~ ^[0-9a-f]{64}$ ]] || { echo 'Pass the SHA256SUMS digest printed by cargo xtask package' >&2; exit 2; }
[[ "$bundle" == /* && "$home" == /* && "$bin_dir" == /* ]] || { echo 'Paths must be absolute' >&2; exit 2; }
[[ -d "$bundle" && ! -L "$bundle" ]] || { echo 'Bundle is not a directory' >&2; exit 2; }
case "$(uname -s):$(uname -m)" in Darwin:arm64) ;; *) echo 'Agent Bridge currently installs on macOS arm64 only' >&2; exit 2;; esac
work=$(mktemp -d "${TMPDIR:-/tmp}/agent-bridge-install.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp -R "$bundle" "$work/bundle"
bundle="$work/bundle"
# `cp -R` keeps links: a linked root or `bin` would let the checks below read
# and run external, mutable files, so the copy must be real directories and a
# real `SHA256SUMS` file.
[[ -d "$bundle" && ! -L "$bundle" && -d "$bundle/bin" && ! -L "$bundle/bin" \
  && -f "$bundle/SHA256SUMS" && ! -L "$bundle/SHA256SUMS" ]] \
  || { echo 'Bundle root, bin or SHA256SUMS is a link or missing; nothing was executed' >&2; exit 1; }
actual=$(shasum -a 256 "$bundle/SHA256SUMS" | awk '{print $1}')
[[ "$actual" == "$sums" ]] || { echo 'SHA256SUMS does not match the attested digest; nothing was executed' >&2; exit 1; }
expected=(release-manifest.json bin/bridge bin/bridge-root-mcp bin/bridge-root-relay bin/bridge-native-daemon bin/bridge-hook bin/bridge-daemon)
(($(wc -l < "$bundle/SHA256SUMS") == ${#expected[@]})) || { echo 'SHA256SUMS lists unexpected entries; nothing was executed' >&2; exit 1; }
for name in "${expected[@]}"; do
  [[ -f "$bundle/$name" && ! -L "$bundle/$name" ]] || { echo "Missing $name; nothing was executed" >&2; exit 1; }
  hash=$(awk -v n="$name" '$2 == n {count++; h=$1} END {if (count != 1) exit 1; print h}' "$bundle/SHA256SUMS") \
    || { echo "SHA256SUMS must list $name exactly once" >&2; exit 1; }
  [[ "$(shasum -a 256 "$bundle/$name" | awk '{print $1}')" == "$hash" ]] \
    || { echo "Checksum mismatch for $name; nothing was executed" >&2; exit 1; }
done
"$bundle/bin/bridge" self-install --bundle "$bundle" --home "$home" --bin-dir "$bin_dir" --sums-sha256 "$sums"
