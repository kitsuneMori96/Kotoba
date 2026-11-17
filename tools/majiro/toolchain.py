"""Pinned, offline MajiroTools build and isolated assembler/disassembler calls."""

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
from xml.sax.saxutils import escape


REVISION = "e0261df508b6c8065865bb51b4059263cef84394"
PATCH_SHA256 = "cd722d03cb728c077626d85bc35abe4554038e15ea0c3ac3acdbcf7799373174"
VENDOR = Path(__file__).resolve().parent / "vendor"
METADATA_NAME = "toolchain.metadata.json"
TIMEOUT = 180
MAGIC = b"MajiroObjV1.000\0"
ENCRYPTED_MAGIC = b"MajiroObjX1.000\0"
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_DIAGNOSTIC = re.compile(
    r"\b(?:errors?|failed|failures?|fatal|\w*exception|invalid|unsupported)\b"
    r"|\b(?:unable to|could not|cannot|can't|not enough arguments)\b", re.I
)
_DIFF_FLAGS = [
    "--no-ext-diff", "--no-textconv", "--binary", "--full-index", "--no-renames",
    "--no-color", "--src-prefix=a/", "--dst-prefix=b/", "--unified=3",
    "--no-indent-heuristic", "--ignore-submodules=none", "--no-relative",
]


class ToolchainError(RuntimeError):
    """A build or tool invocation failed validation (even if its exit code is 0)."""


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _regular(path):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise ToolchainError(f"Missing file: {path}") from exc
    if (not path.is_file() or path.is_symlink()
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise ToolchainError(f"Expected an ordinary file: {path}")
    return path


def _environment(encoding="cp932"):
    if encoding not in ("cp932", "utf8"):
        raise ValueError("encoding must be exactly 'cp932' or 'utf8'")
    env = {key: value for key, value in os.environ.items()
           if key.upper() != "MAJIRO_STRENC"}
    if encoding == "utf8":
        env["MAJIRO_STRENC"] = "utf8"
    env.update({
        "DOTNET_ROLL_FORWARD": "LatestMajor",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true",
        "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH": "false",
        "DOTNET_NOLOGO": "1",
        "DOTNET_CLI_UI_LANGUAGE": "en-US",
        "NUGET_XMLDOC_MODE": "skip",
        "NUGET_CERT_REVOCATION_MODE": "offline",
        "MSBuildEnableWorkloadResolver": "false",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    return env


def _dotnet():
    candidates = [shutil.which("dotnet")]
    for name in ("DOTNET_ROOT", "DOTNET_ROOT_X64"):
        if os.environ.get(name):
            candidates.append(str(Path(os.environ[name]) / "dotnet.exe"))
    if os.name == "nt":
        candidates.append("D:/soft/SDK/dotnet/dotnet.exe")
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise ToolchainError("Local dotnet SDK/runtime not found; installation/download is disabled")


def _text(data):
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else (data or "")


def _run(args, *, cwd, env=None, diagnostics=False):
    try:
        result = subprocess.run(
            [str(arg) for arg in args], cwd=str(cwd), env=env or _environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=TIMEOUT, shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        detail = (_text(exc.stdout) + "\n" + _text(exc.stderr)).strip()[-8000:]
        raise ToolchainError(f"Command timed out after {TIMEOUT}s: {args[0]}\n{detail}") from exc
    except OSError as exc:
        raise ToolchainError(f"Cannot run local command {args[0]}: {exc}") from exc
    output = _text(result.stdout) + "\n" + _text(result.stderr)
    # MSBuild emits '0 Error(s)' on success. Do not mistake that count for an error.
    diagnostic_text = re.sub(r"(?im)^\s*0 Error\(s\)\s*$", "", _ANSI.sub("", output))
    if result.returncode or (diagnostics and _DIAGNOSTIC.search(diagnostic_text)):
        raise ToolchainError(
            f"Command failed validation (exit {result.returncode}): {args[0]}\n"
            + output.strip()[-8000:]
        )
    return result.stdout


def _check_mjo(data, *, unencrypted=False):
    allowed = (MAGIC,) if unencrypted else (MAGIC, ENCRYPTED_MAGIC)
    if len(data) < 32 or data[:16] not in allowed:
        raise ToolchainError("Invalid MJO magic or truncated header")
    entry, _, count = struct.unpack_from("<III", data, 16)
    code_start = 32 + count * 8
    if code_start > len(data):
        raise ToolchainError("Truncated MJO function index")
    code_size = struct.unpack_from("<I", data, code_start - 4)[0]
    if code_size < 2 or code_start + code_size != len(data) or entry >= code_size:
        raise ToolchainError("Invalid MJO bytecode length or entry point")


class Toolchain:
    def __init__(self, path):
        self.path = _regular(Path(path).absolute()).resolve()
        if self.path.name.lower() not in ("maji.dll", "maji.exe"):
            raise ToolchainError("Toolchain path must name maji.dll or maji.exe")

    def _invoke(self, content, operation, encoding):
        env = _environment(encoding)
        prefix = [_dotnet(), str(self.path)] if self.path.suffix.lower() == ".dll" else [str(self.path)]
        with tempfile.TemporaryDirectory(prefix="kotoba-maji-") as temp:
            work = Path(temp).resolve()
            env["DOTNET_CLI_HOME"] = str(work)
            if operation == "disassemble":
                source, target = work / "input.mjo", work / "input.mjil"
                flags = ["-e=false", "-q"]
            else:
                source, target = work / "input.mjil", work / "input.mjo"
                flags = ["--externalized=false", "--encrypt=false", "-q"]
            source.write_bytes(content)
            # A new private directory and absent target exclude stale-output success.
            if target.exists():
                raise ToolchainError("Output unexpectedly exists before invocation")
            _run(prefix + [operation, str(source)] + flags,
                 cwd=work, env=env, diagnostics=True)
            result = _regular(target).read_bytes()
            if not result:
                raise ToolchainError("Tool produced an empty output file")
            return result

    def disassemble(self, data: bytes, encoding: str) -> str:
        _environment(encoding)
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        _check_mjo(data)
        output = self._invoke(data, "disassemble", encoding)
        try:
            text = output.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            raise ToolchainError("Disassembler output is not UTF-8 MJIL") from exc
        if not text.strip():
            raise ToolchainError("Disassembler produced blank MJIL")
        return text

    def assemble(self, text: str, encoding: str) -> bytes:
        _environment(encoding)
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not text.strip():
            raise ToolchainError("Cannot assemble empty MJIL")
        result = self._invoke(text.encode("utf-8"), "assemble", encoding)
        _check_mjo(result, unencrypted=True)
        return result

    def verify(self):
        return verify_toolchain(self.path)


def _vendor_metadata():
    try:
        meta = json.loads((VENDOR / "metadata.json").read_text(encoding="utf-8"))
        if (meta["schema_version"] != 1 or meta["upstream"]["revision"] != REVISION
                or meta["patch"]["sha256"] != PATCH_SHA256):
            raise ToolchainError("Unexpected vendor baseline or patch")
        for section in ("patch", "license", "opcode"):
            record = meta[section]
            path = VENDOR / _safe_relative(record["file"])
            if _sha256(_regular(path).read_bytes()) != record["sha256"]:
                raise ToolchainError(f"Vendor {section} checksum mismatch")
        return meta
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ToolchainError(f"Invalid vendor metadata: {exc}") from exc


def _git(source, *args):
    return _run(["git", "-C", str(source), *args], cwd=source)


def _validate_checkout(source, revision, expected_patch=b"", changed_files=None):
    if not source.is_dir():
        raise ToolchainError(f"Local checkout is missing: {source}")
    root = Path(_text(_git(source, "rev-parse", "--show-toplevel")).strip()).resolve()
    if root != source.resolve():
        raise ToolchainError(f"Expected a git checkout root: {source}")
    if _text(_git(source, "rev-parse", "HEAD")).strip() != revision:
        raise ToolchainError(f"Local checkout HEAD must be {revision}: {source}")
    # Unknown nonignored files are rejected, but ignored bin/obj artifacts are never copied.
    if _git(source, "ls-files", "--others", "--exclude-standard", "-z"):
        raise ToolchainError(f"Untracked files in local checkout: {source}")
    entries = _git(source, "ls-files", "-v", "-z").split(b"\0")
    if any(entry and not entry.startswith(b"H ") for entry in entries):
        raise ToolchainError("Unmerged, assume-unchanged or skip-worktree entries are not allowed")
    diff = _git(source, "diff", *_DIFF_FLAGS, "HEAD", "--")
    if diff not in (b"", expected_patch):
        raise ToolchainError(f"Unknown working-tree changes; only the fixed codec patch is allowed: {source}")
    # Check the index separately, including staged changes reverted only in the working tree.
    staged = _git(source, "diff", "--cached", "--name-only", "--no-renames", "-z", "HEAD", "--")
    for name in staged.split(b"\0"):
        if not name:
            continue
        name = name.decode("utf-8")
        if name not in (changed_files or {}):
            raise ToolchainError(f"Unknown staged change: {name}")
        digest = _sha256(_git(source, "show", ":" + name))
        if digest not in changed_files[name].values():
            raise ToolchainError(f"Unexpected staged contents: {name}")
    return "patched" if diff else "clean"


def _safe_relative(name):
    parts = name.split("/")
    if (not name or "\\" in name or any(
            not part or part in (".", "..") or part.endswith((".", " "))
            or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
            or re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", part, re.I)
            for part in parts)):
        raise ToolchainError(f"Unsafe archive/metadata path: {name!r}")
    return PurePosixPath(name)


def _extract_archive(data, target):
    """Extract only ordinary git files/directories; never follow links or traversal."""
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            relative = _safe_relative(member.name.rstrip("/") if member.isdir() else member.name)
            key = str(relative).casefold()
            if key in seen or not (member.isdir() or member.isfile()):
                raise ToolchainError(f"Duplicate path or nonregular archive member: {member.name}")
            seen.add(key)
            destination = target.joinpath(*relative.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output)


def _inventory(root):
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
            raise ToolchainError(f"Linked build output is not allowed: {path}")
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == METADATA_NAME:
            continue
        data = _regular(path).read_bytes()
        files[relative] = {"size": len(data), "sha256": _sha256(data)}
    return files


def _smoke_test(tool):
    results = {}
    for encoding, literal in (("cp932", "テスト"), ("utf8", "合成测试")):
        literal += "\ue081\ue001"
        text = ('readmark disable\nfunc $12345678() entrypoint {\nentry:\n'
                ' argcheck []\n alloca []\n text "' + literal + '"\n'
                ' proc\n ldc.i 0\n ret\n}\n')
        data = tool.assemble(text, encoding)
        decoded = tool.disassemble(data, encoding)
        if literal not in decoded or tool.assemble(decoded, encoding) != data:
            raise ToolchainError(f"Synthetic {encoding} codec roundtrip failed")
        results[encoding] = _sha256(data)
    return results


def verify_toolchain(path):
    """Verify a published directory (or maji path) against its recorded file digests."""
    path = Path(path).absolute()
    root = path if path.is_dir() else path.parent
    try:
        meta = json.loads(_regular(root / METADATA_NAME).read_text(encoding="utf-8"))
        vendor = _vendor_metadata()
        if (meta["schema_version"] != 1 or meta["status"] != "verified"
                or meta["baseline"]["upstream"] != vendor["upstream"]
                or meta["baseline"]["submodules"] != vendor["submodules"]
                or meta["baseline"]["archive_sha256"] != vendor["archive_sha256"]
                or meta["patch"] != vendor["patch"]
                or meta["vendor_metadata_sha256"] != _sha256((VENDOR / "metadata.json").read_bytes())
                or meta["build"]["target_framework"] != "net7.0"
                or meta["build"]["configuration"] != "Release"
                or meta["build"]["language_version"] != "11.0"
                or meta["build"]["roll_forward"] != "LatestMajor"
                or meta["build"]["network"] != "disabled"
                or set(meta["smoke_tests"]) != {"cp932", "utf8"}):
            raise ToolchainError("Toolchain provenance does not match the fixed baseline/build")
        for name in meta["files"]:
            _safe_relative(name)
        if not {"maji.dll", "maji.deps.json", "maji.runtimeconfig.json", "MajiroLib.dll", "LICENSE"} <= meta["files"].keys():
            raise ToolchainError("Incomplete runtime file manifest")
        if _inventory(root) != meta["files"]:
            raise ToolchainError("Toolchain build file checksum/size or file set mismatch")
        return meta
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ToolchainError(f"Invalid toolchain metadata: {exc}") from exc


def build_toolchain(source_path, output_path) -> Path:
    source = Path(source_path).resolve()
    output = Path(output_path).absolute()
    if output.exists() or output.is_symlink():
        raise ToolchainError(f"Refusing to overwrite existing output: {output}")
    if not output.parent.is_dir():
        raise ToolchainError(f"Output parent must already exist: {output.parent}")
    if output.resolve().is_relative_to(source):
        raise ToolchainError("Output must not be inside the input checkout")
    vendor = _vendor_metadata()
    patch = (VENDOR / vendor["patch"]["file"]).read_bytes()
    state = _validate_checkout(source, REVISION, patch, vendor["patch"]["files"])
    for relative, record in vendor["submodules"].items():
        _validate_checkout(source / _safe_relative(relative), record["revision"])
        gitlink = _text(_git(source, "ls-tree", REVISION, "--", relative)).strip()
        if not gitlink.startswith("160000 commit " + record["revision"] + "\t"):
            raise ToolchainError("Submodule revision does not match the baseline gitlink")
    dotnet = _dotnet()
    with tempfile.TemporaryDirectory(prefix="kotoba-maji-build-") as temp:
        work = Path(temp).resolve()
        extracted = work / "source"
        extracted.mkdir()
        archives = {}
        for relative, checkout, revision in [
            (".", source, REVISION),
            *((name, source / name, record["revision"])
              for name, record in vendor["submodules"].items()),
        ]:
            # git archive otherwise honors the caller's core.autocrlf setting.
            archive = _git(checkout, "-c", "core.autocrlf=false", "archive", "--format=tar", revision)
            archives[relative] = _sha256(archive)
            if archives[relative] != vendor["archive_sha256"][relative]:
                raise ToolchainError(f"Baseline archive checksum mismatch: {relative}")
            _extract_archive(archive, extracted if relative == "." else extracted / relative)
        for name, record in vendor["patch"]["files"].items():
            if _sha256((extracted / name).read_bytes()) != record["baseline_sha256"]:
                raise ToolchainError(f"Baseline file checksum mismatch: {name}")
        _git(extracted, "apply", "--check", "--whitespace=nowarn", str(VENDOR / vendor["patch"]["file"]))
        _git(extracted, "apply", "--whitespace=nowarn", str(VENDOR / vendor["patch"]["file"]))
        for name, record in vendor["patch"]["files"].items():
            if _sha256((extracted / name).read_bytes()) != record["patched_sha256"]:
                raise ToolchainError(f"Patched file checksum mismatch: {name}")

        env = _environment()
        env.update({"DOTNET_CLI_HOME": str(work / "home"),
                    "NUGET_PACKAGES": str(work / "packages"),
                    "NUGET_HTTP_CACHE_PATH": str(work / "http-cache"),
                    "NUGET_PLUGINS_CACHE_PATH": str(work / "plugin-cache")})
        # No inherited credential plugins, audit feeds, fallback feeds or sources.
        for key in list(env):
            if key.upper().startswith(("NUGET_PLUGIN", "NUGET_CREDENTIALPROVIDER")):
                env.pop(key)
        cache = Path(os.environ.get("NUGET_PACKAGES", str(Path.home() / ".nuget" / "packages"))).absolute()
        if str(cache).startswith(("\\\\", "//")) or not cache.is_dir():
            cache = work / "empty-feed"
            cache.mkdir()
        config = work / "NuGet.Config"
        config.write_text(
            '<?xml version="1.0" encoding="utf-8"?><configuration>'
            '<packageSources><clear/><add key="local-cache" value="'
            + escape(str(cache), {'"': '&quot;'}) + '"/></packageSources>'
            '<fallbackPackageFolders><clear/></fallbackPackageFolders>'
            '<auditSources><clear/></auditSources></configuration>', encoding="utf-8")
        project = extracted / vendor["build"]["project"]
        sdk = _text(_run([dotnet, "--version"], cwd=work, env=env)).strip()
        # net7 shipped with C# 11; do not let upstream's 'preview' opt into
        # newer span overload resolution (bytes.Reverse() can become void).
        properties = ["-p:LangVersion=11.0", "-p:NuGetAudit=false", "-p:UseAppHost=false",
                      "-p:RestoreIgnoreFailedSources=false", "-p:RestoreAdditionalProjectSources=",
                      "-p:RestoreFallbackFolders=", "-p:RestoreAdditionalProjectFallbackFolders="]
        try:
            _run([dotnet, "restore", str(project), "--configfile", str(config),
                  "--source", str(cache), *properties], cwd=work, env=env, diagnostics=True)
        except ToolchainError as exc:
            raise ToolchainError(
                "Offline NuGet restore incomplete; no download/installation was attempted. "
                "Required package archives or net7.0 targeting packs may be missing.\n" + str(exc)
            ) from exc
        built = work / "built"
        _run([dotnet, "build", str(project), "--no-restore", "--configuration", "Release",
              "--framework", "net7.0", "--output", str(built), *properties,
              "-p:Deterministic=true", "-p:ContinuousIntegrationBuild=true",
              "-p:PathMap=" + str(extracted) + "=/_/MajiroTools"],
             cwd=work, env=env, diagnostics=True)
        tool = Toolchain(built / "maji.dll")
        smoke = _smoke_test(tool)
        assets = project.parent / "obj" / "project.assets.json"
        shutil.copyfile(VENDOR / vendor["license"]["file"], built / "LICENSE")
        metadata = {
            "schema_version": 1, "status": "verified",
            "baseline": {"upstream": vendor["upstream"], "submodules": vendor["submodules"],
                         "archive_sha256": archives, "checkout_state": state},
            "patch": vendor["patch"],
            "vendor_metadata_sha256": _sha256((VENDOR / "metadata.json").read_bytes()),
            "build": {"configuration": "Release", "target_framework": "net7.0",
                      "language_version": "11.0", "roll_forward": "LatestMajor", "network": "disabled",
                      "sdk_version": sdk, "dotnet_sha256": _sha256(Path(dotnet).read_bytes()),
                      "assets_sha256": _sha256(assets.read_bytes()),
                      "packages": sorted(json.loads(assets.read_text(encoding="utf-8"))["libraries"])},
            "smoke_tests": smoke, "files": _inventory(built),
        }
        (built / METADATA_NAME).write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        verify_toolchain(built)
        # Reserve the destination exclusively only after a complete validated build.
        output.mkdir(exist_ok=False)
        try:
            for path in built.iterdir():
                if path.is_dir():
                    shutil.copytree(path, output / path.name)
                else:
                    shutil.copy2(path, output / path.name)
            verify_toolchain(output)
        except BaseException:
            shutil.rmtree(output)
            raise
    return output.resolve() / "maji.dll"
