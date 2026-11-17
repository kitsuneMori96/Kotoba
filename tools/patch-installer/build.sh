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

# Installer icon comes from the untouched game exe, so no game art is committed.
wslpath_u() {
  local p=${1//\\//}
  if [[ $p =~ ^([A-Za-z]):(.*)$ ]]; then
    printf '/mnt/%s%s' "$(printf '%s' "${BASH_REMATCH[1]}" | tr 'A-Z' 'a-z')" "${BASH_REMATCH[2]}"
  elif [[ $p =~ ^/([A-Za-z])/(.*)$ ]]; then
    printf '/mnt/%s/%s' "$(printf '%s' "${BASH_REMATCH[1]}" | tr 'A-Z' 'a-z')" "${BASH_REMATCH[2]}"
  else
    printf '%s' "$p"
  fi
}
icon_exe="$pristine/ルリのかさね.exe"
if [ ! -f "$icon_exe" ]; then
  echo "missing $icon_exe for the installer icon" >&2
  exit 1
fi
wsl.exe -e bash -lc "python3 '$(wslpath_u "$here/make_icon.py")' '$(wslpath_u "$icon_exe")' '$(wslpath_u "$here/stub/game.ico")' && cd '$(wslpath_u "$here/stub")' && i686-w64-mingw32-windres stub.rc -O coff -o rsrc_windows_386.syso"

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
