import json
import os
import re
from pathlib import Path

from .arc import Archive, ValidationError, file_sha256, name_key, regular_file, safe_name, sha256


def load_json(path):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    with Path(path).open(encoding="utf-8-sig") as stream:
        return json.load(stream, object_pairs_hook=unique_pairs)


def new_json(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _mjo_error(data):
    from .mjo import Script
    try:
        Script(data)
    except ValidationError as exc:
        return str(exc)
    return None


def _scripts(root, optional_base=False):
    entries, archives = {}, []
    for filename in ("scenario.arc", "update.arc"):
        path = root / filename
        if optional_base and filename == "scenario.arc" and not path.exists():
            continue
        arc = Archive(path)
        archives.append({"file": filename, "sha256": file_sha256(path), "entries": len(arc.entries)})
        for entry in arc.entries:
            if not entry.name.lower().endswith(".mjo"):
                continue
            key = name_key(entry.name)
            data = arc.read(entry.name)
            item = {"archive": filename, "sha256": sha256(data), "size": entry.size, "validation_error": _mjo_error(data)}
            if key not in entries:
                entries[key] = {"name": entry.name, "versions": []}
            entries[key]["versions"].append(item)
            entries[key]["selected"] = item
        arc._check_unchanged()
    return entries, archives


def _loose(root):
    result = {}
    folder = root / "scenario"
    if not folder.exists():
        return result
    for current, dirs, files in os.walk(folder, followlinks=False):
        for path in [Path(current), *(Path(current) / name for name in dirs)]:
            info = path.lstat()
            if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValidationError(f"Linked scenario directory is not supported: {path}")
        for filename in files:
            if not filename.lower().endswith(".mjo"):
                continue
            path = Path(current) / filename
            regular_file(path)
            name = path.relative_to(folder).as_posix()
            key = name_key(name)
            if key in result:
                raise ValidationError("Duplicate loose script name")
            data = path.read_bytes()
            result[key] = {"file": "scenario/" + name, "sha256": sha256(data), "validation_error": _mjo_error(data)}
    return result


def _changes(path):
    if path is None:
        return {}
    document = load_json(path)
    if not isinstance(document, dict) or document.get("schema") != 1 or not isinstance(document.get("changes"), list):
        raise ValidationError("Expected allowlist schema 1 with changes array")
    result = {}
    for change in document["changes"]:
        if not isinstance(change, dict) or set(change) != {"name", "base_sha256", "sha256", "reason"}:
            raise ValidationError("Invalid allowlist entry")
        key = name_key(change["name"])
        if key in result or not isinstance(change["reason"], str) or not change["reason"].strip():
            raise ValidationError("Duplicate or unexplained allowlist entry")
        if any(not isinstance(change[field], str) or not re.fullmatch(r"[0-9a-f]{64}", change[field])
               for field in ("base_sha256", "sha256")):
            raise ValidationError("Invalid allowlist digest")
        result[key] = change
    return result


def audit(original, target, executable, allowlist=None):
    original, target = Path(original), Path(target)
    executable = safe_name(executable)
    official, original_archives = _scripts(original)
    installed, target_archives = _scripts(target, optional_base=True)
    loose = _loose(target)
    changes = _changes(allowlist)
    original_exe, target_exe = original / executable, target / executable
    regular_file(original_exe)
    regular_file(target_exe)
    exe_hash, installed_hash = file_sha256(original_exe), file_sha256(target_exe)
    issues = []
    if exe_hash != installed_hash:
        issues.append({"issue": "executable_mismatch"})
    rows, used_changes = [], set()
    for key in sorted(set(official) | set(installed) | set(loose)):
        source, current, loose_file = official.get(key), installed.get(key), loose.get(key)
        row = {"name": (source or current or {"name": key})["name"], "official": source,
               "target": current, "loose": loose_file, "issues": []}
        if source and source["selected"]["validation_error"]:
            row["issues"].append("invalid_official_mjo")
        if current and current["selected"]["validation_error"]:
            row["issues"].append("invalid_target_mjo")
        if loose_file and loose_file["validation_error"]:
            row["issues"].append("invalid_loose_mjo")
        if source is None:
            row["issues"].append("not_in_official_archives")
        elif current is None:
            row["issues"].append("missing_from_target_archives")
        else:
            before, after = source["selected"]["sha256"], current["selected"]["sha256"]
            if before != after:
                allowed = changes.get(key)
                if allowed and (allowed["base_sha256"], allowed["sha256"]) == (before, after):
                    row["approved_change"] = allowed["reason"]
                    used_changes.add(key)
                else:
                    row["issues"].append("unapproved_archive_change")
            if loose_file and loose_file["sha256"] != after:
                row["issues"].append("loose_archive_conflict")
        if row["issues"]:
            issues.append({"name": row["name"], "issues": row["issues"]})
        rows.append(row)
    for key in sorted(set(changes) - used_changes):
        issues.append({"name": changes[key]["name"], "issue": "unused_or_stale_allowlist_entry"})
    return {"schema": 1, "input_policy": "official update.arc overrides scenario.arc; runtime order not inferred",
            "original": str(original.resolve()), "target": str(target.resolve()),
            "executable": {"file": executable, "original_sha256": exe_hash, "target_sha256": installed_hash},
            "original_archives": original_archives, "target_archives": target_archives,
            "counts": {"official_scripts": len(official), "target_scripts": len(installed),
                       "loose_scripts": len(loose), "unresolved": len(issues)},
            "safe_to_build": not issues, "issues": issues, "scripts": rows}
