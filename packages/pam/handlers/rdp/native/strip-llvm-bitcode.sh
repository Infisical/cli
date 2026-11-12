#!/usr/bin/env bash
# Since Go 1.26.11 (CVE-2026-97038), `go build` refuses to link any library under a -L directory named
# in a #cgo LDFLAGS directive if its objects carry LLVM bitcode sections, and Rust's precompiled
# standard library ships with bitcode embedded. The bridge's directive names target/release, so a
# `cargo build --release` followed by `go build -tags rdp` fails until this runs. The linker never
# reads those sections, so removing them leaves the linked code unchanged.
#
# Release builds don't need it: they pass the per-target directory in CGO_LDFLAGS, which Go doesn't
# scan. Don't use it on a Windows (COFF) archive: Go 1.26.11 rejects the stripped result.
#
# Usage: strip-llvm-bitcode.sh <cargo release dir>, e.g. strip-llvm-bitcode.sh target/release
set -euo pipefail

dir=${1:?usage: strip-llvm-bitcode.sh <cargo release dir>}
host=$(rustc -vV | sed -n 's/^host: //p')
objcopy="$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-objcopy"
if [ ! -x "$objcopy" ] && [ ! -x "$objcopy.exe" ]; then
  echo "llvm-objcopy not found in the Rust toolchain; run: rustup component add llvm-tools" >&2
  exit 1
fi

# Go checks every library under the -L directory, including the copy Cargo keeps in deps/.
stripped=0
for lib in "$dir"/libinfisical_rdp_bridge.a "$dir"/deps/libinfisical_rdp_bridge-*.a; do
  [ -f "$lib" ] || continue
  "$objcopy" \
    --remove-section=.llvmbc --remove-section=.llvmcmd \
    --remove-section=__LLVM,__bitcode --remove-section=__LLVM,__cmdline \
    "$lib"
  stripped=$((stripped + 1))
done
if [ "$stripped" = 0 ]; then
  echo "no libinfisical_rdp_bridge.a in $dir" >&2
  exit 1
fi
echo "removed LLVM bitcode from $stripped archive(s) in $dir"
