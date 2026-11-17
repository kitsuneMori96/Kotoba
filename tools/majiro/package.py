import contextlib
import ctypes
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path

from .arc import Archive, ValidationError, file_sha256, name_key, regular_file, safe_name, sha256
from .audit import load_json, new_json
from .mjo import Script

_STATE = ".kotoba-state"
_LOCK = b"KOTOBA-LOCK-1\n"
_ARCS = {"scenario.arc", "update.arc", "fastdata.arc", "data.arc", "data2.arc"}
_FILE_FIELDS = {"path", "before_sha256", "after_sha256", "size", "payload", "reason"}


def _fail(message):
    raise ValidationError(message)


def _absolute(path):
    path = Path(path)
    if ".." in path.parts:
        _fail(f"Parent traversal is not supported: {path}")
    return Path(os.path.abspath(path))


def _exists(path):
    return os.path.lexists(path)


def _unlinked(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        _fail(f"Linked/reparse path is not supported: {path}")
    return info


def _directory(path):
    path = _absolute(path)
    for part in (*reversed(path.parents), path):
        if not stat.S_ISDIR(_unlinked(part).st_mode):
            _fail(f"Expected an existing ordinary directory: {part}")
    return path


def _file(path, private=False):
    path = _absolute(path)
    _directory(path.parent)
    info = regular_file(path)
    if private and info.st_nlink != 1:
        _fail(f"State/temporary file has external hard links: {path}")
    return info


def _child(root, name):
    """Resolve case-insensitively, checking every existing ancestor, not resolve()."""
    current = _directory(root)
    parts = safe_name(name).split("/")
    for index, part in enumerate(parts):
        matches = [p for p in current.iterdir() if p.name.casefold() == part.casefold()]
        if len(matches) > 1:
            _fail(f"Ambiguous case aliases: {current / part}")
        if not matches:
            return current.joinpath(*parts[index:])
        current = matches[0]
        info = _unlinked(current)
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            _fail(f"Non-directory path prefix: {current}")
    return current


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        _fail("Expected an exact lowercase SHA-256 digest")
    return value


def _object(value, fields, optional=()):
    if not isinstance(value, dict) or not fields <= value.keys() or value.keys() - fields - set(optional):
        _fail("Unexpected or missing document fields")


def _schema(value):
    if type(value) is not int or value != 1:
        _fail("Only schema 1 is supported")


def _executable(value):
    _object(value, {"path", "sha256"})
    path = safe_name(value["path"])
    if not path.casefold().endswith(".exe"):
        _fail("The host must be an EXE")
    return {"path": path, "sha256": _digest(value["sha256"])}


def _purpose(path):
    path = safe_name(path)
    key = name_key(path)
    if key != "winmm.dll" and key not in _ARCS and not (key.startswith("scenario/") and key.endswith(".mjo")):
        _fail(f"Not an approved patch destination: {path}")
    return path


def _distinct(paths):
    keys = sorted(name_key(path) for path in paths)
    if len(keys) != len(set(keys)):
        _fail("Duplicate case-insensitive paths")
    seen = set(keys)
    for key in keys:
        parts = key.split("/")
        if any("/".join(parts[:i]) in seen for i in range(1, len(parts))):
            _fail("Conflicting file/directory prefixes")


def _base_entry(item):
    path = _purpose(item["path"])
    before = item["before_sha256"]
    if before is not None:
        _digest(before)
    elif name_key(path) in _ARCS:
        _fail("Archive replacements require an exact before digest")
    if not isinstance(item["reason"], str) or not item["reason"].strip():
        _fail("Every replacement needs a nonempty reason")
    return path


def _manifest(value):
    _object(value, {"schema", "executable", "files"}, {"audit"})
    _schema(value["schema"])
    _executable(value["executable"])
    if not isinstance(value["files"], list) or not value["files"]:
        _fail("Expected a nonempty files array")
    for i, item in enumerate(value["files"]):
        _object(item, _FILE_FIELDS)
        _base_entry(item)
        _digest(item["after_sha256"])
        if type(item["size"]) is not int or item["size"] < 0:
            _fail("Invalid payload size")
        if item["payload"] != f"payload/{i:06d}.bin":
            _fail("Payloads must have their assigned numeric names")
    _distinct(item["path"] for item in value["files"])
    return value


def _json(path):
    _file(path)
    try:
        return load_json(path)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValidationError(f"Invalid JSON: {path}") from exc


def _host(root, executable):
    path = _child(root, executable["path"])
    _file(path)
    if file_sha256(path) != executable["sha256"]:
        _fail("Host executable version/hash mismatch")
    return path


def _current(root, item):
    path = _child(root, item["path"])
    if not _exists(path):
        return path, None, 0
    info = _file(path)
    return path, file_sha256(path), info.st_size


def _before(root, manifest):
    _host(root, manifest["executable"])
    for item in manifest["files"]:
        _, digest, _ = _current(root, item)
        if digest != item["before_sha256"]:
            _fail(f"Installation precondition mismatch: {item['path']}")
    if any(name_key(item["path"]) == "winmm.dll" for item in manifest["files"]):
        _file(_child(root, "winmm_orig.dll"))


def _loose(root):
    folder = _child(root, "scenario")
    if not _exists(folder):
        return {}
    _directory(folder)
    result = {}
    for current, dirs, files in os.walk(folder, followlinks=False):
        current = _directory(current)
        _distinct([*dirs, *files])
        for name in dirs:
            _directory(current / name)
        for name in files:
            if not name.casefold().endswith(".mjo"):
                continue
            path = current / name
            _file(path)
            key = name_key("scenario/" + path.relative_to(folder).as_posix())
            if key in result:
                _fail("Duplicate loose script")
            result[key] = file_sha256(path)
    return result


def _same_path(left, right):
    # samefile also handles Windows short (8.3) names emitted by tempfile.
    # Check ancestors first: resolving aliases must not conceal a junction.
    try:
        return os.path.samefile(_directory(left), _directory(right))
    except OSError:
        return False


def _audit(root, executable, document):
    if not isinstance(document, dict) or document.get("safe_to_build") is not True:
        _fail("Script updates require a successful audit")
    if document.get("issues", []) != []:
        _fail("Audit still contains unresolved issues")
    if "counts" in document and (not isinstance(document["counts"], dict)
                                  or document["counts"].get("unresolved") != 0):
        _fail("Audit unresolved count is not zero")
    _schema(document.get("schema"))
    if not isinstance(document.get("target"), str) or not _same_path(document["target"], root):
        _fail("Audit belongs to another target")
    exe = document.get("executable")
    if (not isinstance(exe, dict) or name_key(exe.get("file", "")) != name_key(executable["path"])
            or exe.get("target_sha256") != executable["sha256"]
            or exe.get("original_sha256") != executable["sha256"]):
        _fail("Audit executable mismatch")
    archives = document.get("target_archives")
    if not isinstance(archives, list):
        _fail("Missing audited target archives")
    found = set()
    for entry in archives:
        if not isinstance(entry, dict):
            _fail("Invalid audited archive")
        key = name_key(entry.get("file", ""))
        if key not in {"scenario.arc", "update.arc"} or key in found:
            _fail("Unexpected or duplicate audited archive")
        found.add(key)
        path = _child(root, entry["file"])
        _file(path)
        if file_sha256(path) != _digest(entry.get("sha256")):
            _fail("Audited target archive changed")
    actual = {name for name in ("scenario.arc", "update.arc") if _exists(_child(root, name))}
    if "update.arc" not in found or found != actual:
        _fail("Incomplete target archive audit")
    scripts = document.get("scripts")
    if not isinstance(scripts, list):
        _fail("Missing audited loose inventory")
    expected = {}
    for row in scripts:
        if not isinstance(row, dict) or "loose" not in row or row.get("issues", []) != []:
            _fail("Invalid or unresolved audited script inventory")
        loose = row["loose"]
        if loose is None:
            continue
        if not isinstance(loose, dict):
            _fail("Invalid audited loose script")
        key = name_key(_purpose(loose.get("file", "")))
        if not key.startswith("scenario/") or key in expected:
            _fail("Invalid or duplicate audited loose path")
        expected[key] = _digest(loose.get("sha256"))
    if expected != _loose(root):
        _fail("Audited loose scripts changed (hash or inventory)")


def _check_audit(root, manifest):
    scripts = any(name_key(item["path"]) in {"scenario.arc", "update.arc"}
                  or name_key(item["path"]).startswith("scenario/") for item in manifest["files"])
    if scripts or "audit" in manifest:
        _audit(root, manifest["executable"], manifest.get("audit"))


def _payloads(root, manifest, sources):
    replacements = {name_key(item["path"]): source for item, source in zip(manifest["files"], sources)}
    script_archives = {}
    for key, source in replacements.items():
        if key in _ARCS:
            archive = Archive(source)
            if key in {"scenario.arc", "update.arc"}:
                script_archives[key] = archive
        elif key.startswith("scenario/"):
            Script(source.read_bytes())
    if not any(key in {"scenario.arc", "update.arc"} or key.startswith("scenario/") for key in replacements):
        return
    selected = {}
    for key in ("scenario.arc", "update.arc"):
        if key in script_archives:
            archive = script_archives[key]
        else:
            path = _child(root, key)
            if not _exists(path):
                continue
            archive = Archive(path)
        for entry in archive.entries:
            if entry.name.casefold().endswith(".mjo"):
                data = archive.read(entry.name)
                Script(data)
                selected[name_key(entry.name)] = sha256(data)
        archive._check_unchanged()
    prior_names = {name_key(row["name"]) for row in manifest["audit"]["scripts"]}
    if not prior_names <= selected.keys():
        _fail("Payload removes previously audited scripts")
    loose = _loose(root)
    for key, source in replacements.items():
        if key.startswith("scenario/"):
            loose[key] = file_sha256(source)
    for key, digest in loose.items():
        if selected.get(key.removeprefix("scenario/")) != digest:
            _fail(f"Payload creates a loose/archive conflict: {key}")


def _space(root, required):
    if shutil.disk_usage(root).free < required + 1024 * 1024:
        _fail("Insufficient disk space for backups and temporary copies")


def _sync_directory(path):
    # Windows fsync on the file plus same-directory replace is used; directory
    # fsync is not exposed there. No claim of power-loss/multi-file atomicity.
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _copy_new(source, destination, expected):
    _file(source)
    _directory(destination.parent)
    with source.open("rb") as src, destination.open("xb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())
    if file_sha256(destination) != expected:
        _fail(f"File changed while copying: {source}")
    _sync_directory(destination.parent)


def _source_path(parent, value):
    if not isinstance(value, str) or not value:
        _fail("Expected a payload/audit input path")
    path = Path(value)
    path = path if path.is_absolute() else parent / path
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part == "..":
            _directory(current)  # Never normalize away a link before traversal.
            current = current.parent
        else:
            current = current / part
    _file(current)
    return current


def build(spec_path, target, output):
    """Build only into a new directory outside target; never change target."""
    spec_path, root, output = _absolute(spec_path), _directory(target), _absolute(output)
    _directory(output.parent)
    if _exists(output) or any(os.path.samefile(root, parent) for parent in output.parents):
        _fail("Output must be a new directory outside target")
    spec = _json(spec_path)
    _object(spec, {"schema", "executable", "files"}, {"audit"})
    _schema(spec["schema"])
    executable = _executable(spec["executable"])
    if not isinstance(spec["files"], list) or not spec["files"]:
        _fail("Expected a nonempty files array")
    manifest = {"schema": 1, "executable": executable, "files": []}
    sources = []
    for i, item in enumerate(spec["files"]):
        _object(item, {"path", "source", "before_sha256", "reason"})
        path = _base_entry(item)
        source = _source_path(spec_path.parent, item["source"])
        if source.name.casefold() == "winmm_orig.dll":
            _fail("The system winmm_orig.dll dependency must not be packaged")
        info = _file(source)
        sources.append(source)
        manifest["files"].append({"path": path, "before_sha256": item["before_sha256"],
                                  "after_sha256": file_sha256(source), "size": info.st_size,
                                  "payload": f"payload/{i:06d}.bin", "reason": item["reason"]})
    if "audit" in spec:
        manifest["audit"] = _json(_source_path(spec_path.parent, spec["audit"]))
    _manifest(manifest)
    _before(root, manifest)
    _check_audit(root, manifest)
    _payloads(root, manifest, sources)
    _space(output.parent, sum(item["size"] for item in manifest["files"]))
    output.mkdir()
    (output / "payload").mkdir()
    for source, item in zip(sources, manifest["files"]):
        _copy_new(source, output / item["payload"], item["after_sha256"])
        if (output / item["payload"]).stat().st_size != item["size"]:
            _fail("Payload size changed while building")
    new_json(output / "manifest.json", manifest)
    with (output / "manifest.json").open("r+b") as stream:
        os.fsync(stream.fileno())
    _sync_directory(output)
    return manifest


def _verified(package_dir, target):
    package, root = _directory(package_dir), _directory(target)
    manifest = _manifest(_json(_child(package, "manifest.json")))
    for item in manifest["files"]:
        path = _child(package, item["payload"])
        info = _file(path)
        if info.st_size != item["size"] or file_sha256(path) != item["after_sha256"]:
            _fail(f"Payload hash/size mismatch: {item['path']}")
    _before(root, manifest)
    _check_audit(root, manifest)
    _payloads(root, manifest, [_child(package, item["payload"]) for item in manifest["files"]])
    return package, root, manifest


def _report(status, root, count=0):
    return {"status": status, "target": str(root), "files": count}


def verify(package_dir, target):
    _, root, manifest = _verified(package_dir, target)
    return {**_report("verified", root, len(manifest["files"])),
            "plan": [{key: item[key] for key in ("path", "before_sha256", "after_sha256", "size", "reason")}
                     for item in manifest["files"]]}


def _assert_not_running(executable):
    if os.name != "nt":
        _fail("Process checking requires Windows")
    from ctypes import wintypes as w

    class ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("pid", w.DWORD),
                    ("heap", ctypes.c_size_t), ("module", w.DWORD), ("threads", w.DWORD),
                    ("parent", w.DWORD), ("priority", w.LONG), ("flags", w.DWORD),
                    ("name", w.WCHAR * 260)]

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    api.CreateToolhelp32Snapshot.restype = w.HANDLE
    for name in ("Process32FirstW", "Process32NextW"):
        fn = getattr(api, name)
        fn.argtypes = [w.HANDLE, ctypes.POINTER(ProcessEntry)]
        fn.restype = w.BOOL
    api.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    api.OpenProcess.restype = w.HANDLE
    api.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
    api.QueryFullProcessImageNameW.restype = w.BOOL
    api.CloseHandle.argtypes = [w.HANDLE]
    api.CloseHandle.restype = w.BOOL
    api.GetShortPathNameW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD]
    api.GetShortPathNameW.restype = w.DWORD
    expected = os.path.normcase(os.path.realpath(executable))
    short_name = ctypes.create_unicode_buffer(32768)
    length = api.GetShortPathNameW(expected, short_name, len(short_name))
    if not length or length >= len(short_name):
        _fail("Cannot determine executable path aliases")
    names = {executable.name.casefold(), Path(expected).name.casefold(), Path(short_name.value).name.casefold()}
    snapshot = api.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        _fail("Cannot enumerate running processes")
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        ok = api.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.name.casefold() in names:
                handle = api.OpenProcess(0x1000, False, entry.pid)
                if not handle:
                    _fail("Cannot inspect a possibly running host process")
                try:
                    buffer = ctypes.create_unicode_buffer(32768)
                    size = w.DWORD(len(buffer))
                    if not api.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                        _fail("Cannot read a host process image path")
                    if os.path.normcase(os.path.realpath(buffer.value)) == expected:
                        _fail("Target executable is running")
                finally:
                    api.CloseHandle(handle)
            ok = api.Process32NextW(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            _fail("Process enumeration did not finish reliably")
    finally:
        api.CloseHandle(snapshot)


@contextlib.contextmanager
def _lock(state, create=False):
    _directory(state)
    path = _child(state, "lock")
    if create:
        with path.open("xb") as stream:
            stream.write(_LOCK)
            stream.flush()
            os.fsync(stream.fileno())
    _file(path, private=True)
    with path.open("r+b") as stream:
        locked = False
        try:
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError as exc:
                raise ValidationError("Another transaction owns the state lock") from exc
            if stream.read(len(_LOCK) + 1) != _LOCK:
                _fail("Unrecognized state lock")
            yield
        finally:
            if locked:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    # Keep the lock inode. Unlinking it permits competing holders on two inodes.


def _journal_temp(state, journal):
    return _child(state, f".journal-{journal['id']}.tmp")


def _save(state, journal):
    path = _child(state, "journal.json")
    if _exists(path):
        _file(path, private=True)
    temporary = _journal_temp(state, journal)
    if _exists(temporary):
        _file(temporary, private=True)
        temporary.unlink()  # Exact transaction-owned journal scratch file only.
    new_json(temporary, journal)
    with temporary.open("r+b") as stream:
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    _sync_directory(state)


def _temp_name(journal, index, item):
    parent = safe_name(item["path"]).rpartition("/")[0]
    name = f".kotoba-{journal['id']}-{index:06d}.tmp"
    return f"{parent}/{name}" if parent else name


def _load_state(root, state):
    path = _child(state, "journal.json")
    _file(path, private=True)
    journal = _json(path)
    _object(journal, {"schema", "id", "target", "executable", "status", "files"})
    _schema(journal["schema"])
    if not isinstance(journal["id"], str) or not re.fullmatch(r"[0-9a-f]{32}", journal["id"]):
        _fail("Invalid transaction identifier")
    if not isinstance(journal["target"], str) or not _same_path(journal["target"], root):
        _fail("Transaction belongs to another target")
    if journal["status"] not in ("preparing", "installing", "installed", "recovering", "rolled_back"):
        _fail("Invalid transaction status")
    _executable(journal["executable"])
    if not isinstance(journal["files"], list) or not journal["files"]:
        _fail("Invalid transaction files")
    for i, item in enumerate(journal["files"]):
        _object(item, _FILE_FIELDS | {"backup", "before_size", "state"})
        _manifest({"schema": 1, "executable": journal["executable"],
                   "files": [{**{k: item[k] for k in _FILE_FIELDS}, "payload": "payload/000000.bin"}]})
        if item["payload"] != f"payload/{i:06d}.bin":
            _fail("Invalid journal payload")
        if item["state"] not in ("pending", "backed_up", "applied", "restored"):
            _fail("Invalid per-file transaction state")
        if type(item["before_size"]) is not int or item["before_size"] < 0:
            _fail("Invalid backup size")
        expected = None if item["before_sha256"] is None else f"backups/{i:06d}.bin"
        if item["backup"] != expected or (expected is None and item["before_size"] != 0):
            _fail("Invalid backup location")
    _distinct(item["path"] for item in journal["files"])
    return journal


def _parents(root, name):
    parts = safe_name(name).split("/")[:-1]
    for i in range(1, len(parts) + 1):
        path = _child(root, "/".join(parts[:i]))
        if not _exists(path):
            path.mkdir()
            _sync_directory(path.parent)
        _directory(path)


def _replace_file(source, destination, temporary, digest, expected_before):
    _copy_new(source, temporary, digest)
    _directory(destination.parent)
    current = None
    if _exists(destination):
        _file(destination)
        current = file_sha256(destination)
    if current != expected_before:
        _fail("Destination changed while preparing its atomic replacement")
    os.replace(temporary, destination)
    _sync_directory(destination.parent)


def install(package_dir, target):
    package, root, manifest = _verified(package_dir, target)
    state = _child(root, _STATE)
    if _exists(state):
        _fail("Existing .kotoba-state: recover/rollback it; never overwrite backups")
    _assert_not_running(_host(root, manifest["executable"]))
    journal = {"schema": 1, "id": uuid.uuid4().hex, "target": str(root),
               "executable": manifest["executable"], "status": "preparing", "files": []}
    for i, item in enumerate(manifest["files"]):
        _, digest, size = _current(root, item)
        if digest != item["before_sha256"]:
            _fail("Target changed before transaction preparation")
        journal["files"].append({**item, "before_size": size,
                                 "backup": None if item["before_sha256"] is None else f"backups/{i:06d}.bin",
                                 "state": "pending"})
        if _exists(_child(root, _temp_name(journal, i, item))):
            _fail("Transaction temporary filename already exists")
    _space(root, sum(item["before_size"] + item["size"] for item in journal["files"]))
    state.mkdir()  # Exclusive directory creation arbitrates competing installs.
    _sync_directory(root)
    with _lock(state, create=True):
        _save(state, journal)
        _, _, checked = _verified(package, root)  # Full revalidation under lock.
        if checked != manifest:
            _fail("Package manifest changed between installation checks")
        _assert_not_running(_host(root, manifest["executable"]))
        (state / "backups").mkdir()
        for item in journal["files"]:
            if item["backup"] is not None:
                source, digest, _ = _current(root, item)
                if digest != item["before_sha256"]:
                    _fail("Target changed before backup")
                _copy_new(source, _child(state, item["backup"]), item["before_sha256"])
            item["state"] = "backed_up"
            _save(state, journal)
        _before(root, manifest)
        _check_audit(root, manifest)
        _assert_not_running(_host(root, manifest["executable"]))
        journal["status"] = "installing"
        _save(state, journal)
        for i, item in enumerate(journal["files"]):
            _assert_not_running(_host(root, manifest["executable"]))
            destination, digest, _ = _current(root, item)
            if digest != item["before_sha256"]:
                _fail("Target changed during installation; use recover")
            _parents(root, item["path"])
            _replace_file(_child(package, item["payload"]), destination,
                          _child(root, _temp_name(journal, i, item)), item["after_sha256"], item["before_sha256"])
            item["state"] = "applied"
            _save(state, journal)
        for item in journal["files"]:
            if _current(root, item)[1] != item["after_sha256"]:
                _fail("Target changed before installation completed; use recover")
        journal["status"] = "installed"
        _save(state, journal)
    return _report("installed", root, len(manifest["files"]))


def _restore_preflight(root, state, journal):
    _assert_not_running(_host(root, journal["executable"]))
    plan = []
    for i, item in enumerate(journal["files"]):
        destination, digest, _ = _current(root, item)
        if digest not in (item["before_sha256"], item["after_sha256"]):
            _fail(f"External change/unknown target hash: {item['path']}")
        if journal["status"] == "rolled_back" and digest != item["before_sha256"]:
            _fail("Previously restored target was changed externally")
        backup = None
        if item["backup"] is not None:
            backup = _child(state, item["backup"])
            if _exists(backup):
                info = _file(backup, private=True)
                if info.st_size != item["before_size"] or file_sha256(backup) != item["before_sha256"]:
                    _fail(f"Corrupt backup: {item['path']}")
            elif journal["status"] != "preparing" or digest != item["before_sha256"]:
                _fail(f"Missing backup: {item['path']}")
        temporary = _child(root, _temp_name(journal, i, item))
        if _exists(temporary):
            _file(temporary, private=True)
        plan.append((item, destination, digest, backup, temporary))
    scratch = _journal_temp(state, journal)
    if _exists(scratch):
        _file(scratch, private=True)
    needed = sum(item["before_size"] for item, _, digest, backup, _ in plan
                 if digest != item["before_sha256"] or (backup is not None and not _exists(backup)))
    if needed:
        _space(root, needed)
    return plan


def _restore(target, recovery):
    root = _directory(target)
    state = _child(root, _STATE)
    if not _exists(state):
        return _report("no_transaction", root)
    _directory(state)
    with _lock(state):
        journal = _load_state(root, state)
        if not recovery and journal["status"] not in ("installed", "rolled_back"):
            _fail("Interrupted transaction requires recover, not rollback")
        plan = _restore_preflight(root, state, journal)  # No writes before all checks.
        if journal["status"] == "rolled_back":
            return _report("rolled_back", root, len(plan))
        # A crash while preparing may leave no backup for an untouched file.
        # Keep preparing until recovery completes so another recovery can repeat.
        preparing = journal["status"] == "preparing"
        if not preparing:
            journal["status"] = "recovering"
        _save(state, journal)
        for item, destination, digest, backup, temporary in plan:
            _assert_not_running(_host(root, journal["executable"]))
            now_path, now, _ = _current(root, item)
            if now != digest or now_path != destination:
                _fail("Target changed after recovery preflight")
            if backup is not None and not _exists(backup):
                # Interrupted preparation never touched this target. Complete its
                # snapshot so the retained, rolled-back transaction is repeatable.
                _parents(state, item["backup"])
                _copy_new(destination, backup, item["before_sha256"])
            if _exists(temporary):
                _file(temporary, private=True)
                temporary.unlink()  # Only the exact scratch name recorded by this transaction.
            if digest != item["before_sha256"]:
                if item["before_sha256"] is None:
                    destination.unlink()
                    _sync_directory(destination.parent)
                else:
                    _replace_file(backup, destination, temporary, item["before_sha256"], digest)
            item["state"] = "restored"
            _save(state, journal)
        journal["status"] = "rolled_back"
        _save(state, journal)
    return _report("rolled_back", root, len(plan))


def rollback(target):
    """Restore an installed patch after preflighting every target and backup."""
    return _restore(target, recovery=False)


def recover(target):
    """Restore pre-installation content even when per-file progress is stale."""
    return _restore(target, recovery=True)
