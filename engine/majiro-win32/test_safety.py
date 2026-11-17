import os
import shlex
import subprocess
import tempfile
from pathlib import Path


def run(args):
    subprocess.run([str(arg) for arg in args], check=True)


def wsl_path(path):
    return subprocess.check_output(["wsl.exe", "-e", "wslpath", "-a", "-u", str(path)], text=True).strip()


def main():
    if os.name != "nt":
        raise SystemExit("Run this Win32 suite with Windows Python and WSL MinGW installed")
    root = Path(__file__).resolve().parent
    linux_root = wsl_path(root)
    run(["wsl.exe", "-e", "/usr/bin/bash", "-lc", "CC=/usr/bin/i686-w64-mingw32-gcc OBJDUMP=/usr/bin/i686-w64-mingw32-objdump /usr/bin/bash " + shlex.quote(linux_root + "/build.sh")])
    run(["wsl.exe", "-e", "/usr/bin/python3", linux_root + "/test_legacy.py"])
    with tempfile.TemporaryDirectory(prefix="kotoba-dll-tests-") as temporary:
        folder = Path(temporary)
        linux_temp = wsl_path(folder)
        for name in ("hooks", "mci", "fs"):
            run(["wsl.exe", "-e", "/usr/bin/i686-w64-mingw32-gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-Wno-cast-function-type", "-I", linux_root + "/src", linux_root + "/tests/" + name + "_test.c",
                 "-o", linux_temp + "/" + name + "_test.exe", "-static-libgcc"])
            executable = folder / (name + "_test.exe")
            if name == "hooks":
                for scenario in ("helpers", "badpe", "badimport", "mismatch", "writefail", "valid"):
                    run([executable, scenario])
            else:
                run([executable])
    print("PASS: DLL build, legacy banners, PE/patch failures, MCI flags, file API LastError")


if __name__ == "__main__":
    main()
