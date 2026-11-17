#!/usr/bin/env bash
# Build the single-file installer from the deployed test copy.
# Usage: build.sh [version]
# KOTOBA_PRISTINE must point at a directory holding the untouched game exe and
# the official update.arc/fastdata.arc; the live install is usually already patched.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
version=${1:-1.0.0}
outdir="$root/work/installer-build"
pristine=${KOTOBA_PRISTINE:-}
if [ -z "$pristine" ]; then
  echo "KOTOBA_PRISTINE is required (directory with pristine game exe and arcs)" >&2
  exit 1
fi
mkdir -p "$outdir"

export CGO_ENABLED=0 GOOS=windows GOARCH=386 GOTOOLCHAIN=local
cd "$here"
go build -trimpath -ldflags "-s -w" -o "$outdir/stub.exe" ./stub
go build -trimpath -ldflags "-s -w" -o "$outdir/pack.exe" ./pack

"$outdir/pack.exe" \
  -stub "$outdir/stub.exe" \
  -source "$root/work/ruri-test" \
  -pristine "$pristine" \
  -out "$outdir/KotobaPatch-$version.exe" \
  -version "$version" \
  -note "local private build"

ls -la "$outdir/KotobaPatch-$version.exe"
