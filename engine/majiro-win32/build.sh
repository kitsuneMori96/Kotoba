#!/usr/bin/env bash
# Builds the 32-bit winmm proxy that teaches the Majiro engine UTF-8.
# Run from WSL with mingw-w64 installed: bash build.sh
set -euo pipefail
cd "$(dirname "$0")"

CC=${CC:-i686-w64-mingw32-gcc}
OBJDUMP=${OBJDUMP:-i686-w64-mingw32-objdump}
SYS_WINMM=${SYS_WINMM:-/mnt/c/Windows/SysWOW64/winmm.dll}
OUT=${OUT:-build}

mkdir -p "$OUT"

if [ ! -f "$SYS_WINMM" ]; then
  echo "missing $SYS_WINMM (set SYS_WINMM=/path/to/winmm.dll)" >&2
  exit 1
fi

# Every export of the real winmm is forwarded to a renamed copy, so modules
# other than the game keep working.
{
  echo "LIBRARY winmm"
  echo "EXPORTS"
  "$OBJDUMP" -p "$SYS_WINMM" |
    awk '
      /^\[Ordinal\/Name Pointer\] Table/ { names = 1; next }
      names && /^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+[^[:space:]]/ {
        print $3 "=winmm_orig." $3
      }
    '
} > "$OUT/winmm.def"

rm -f "$OUT/winmm_orig.dll"
cp "$SYS_WINMM" "$OUT/winmm_orig.dll"
chmod u+w "$OUT/winmm_orig.dll"

"$CC" -shared -O2 -s -Wall -Wextra -Wno-cast-function-type \
  -o "$OUT/winmm.dll" \
  src/dllmain.c src/hooks.c src/utf8.c src/gdi.c src/fslog.c \
  "$OUT/winmm.def" \
  -static-libgcc -Wl,--no-insert-timestamp

echo "built $OUT/winmm.dll"
grep -c '=winmm_orig\.' "$OUT/winmm.def" | sed 's/^/forwarded exports: /'
