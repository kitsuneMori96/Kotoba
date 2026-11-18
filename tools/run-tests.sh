#!/usr/bin/env bash
# Single entry point for the regression suites.
#   tools/run-tests.sh            # Python toolchain suite (fast, no game assets)
#   tools/run-tests.sh --engine   # also build and run the Win32 DLL suite
set -euo pipefail
cd "$(dirname "$0")/.."

pick_python() {
  for candidate in python3 python python.exe; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  done
  echo "no Python 3.11+ found (tests use unittest.TestCase.enterContext)" >&2
  return 1
}

PYTHON=$(pick_python)
echo "== Python toolchain suite ($PYTHON: $("$PYTHON" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))'))"

engine=0
args=()
for arg in "$@"; do
  case "$arg" in
    --engine) engine=1 ;;
    *) args+=("$arg") ;;
  esac
done

"$PYTHON" -m unittest discover -s tools/majiro/tests -t . ${args[@]+"${args[@]}"}

if [ "$engine" = 1 ]; then
  echo "== Win32 DLL suite"
  if ! command -v python.exe >/dev/null 2>&1; then
    echo "skipped: needs Windows Python on PATH" >&2
  else
    python.exe engine/majiro-win32/test_safety.py
  fi
else
  echo "== Win32 DLL suite skipped (pass --engine)"
fi
