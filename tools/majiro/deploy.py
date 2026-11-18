"""Deploy a finished chapter into a test ARC: manifest, rebuild, independent diff, backup, restart."""
import json
import os
import shutil
import subprocess
from pathlib import Path

from .arc import Archive, ValidationError, file_sha256, name_key, sha256


def restart_game(executable, image=None):
    """Kill every lingering instance, prove the process list is empty, then start once."""
    executable = Path(executable)
    if not executable.is_absolute():
        raise ValidationError("Restart needs an absolute executable path")
    image = image or executable.name
    environment = {**os.environ, "MSYS_NO_PATHCONV": "1", "GIT_TERMINAL_PROMPT": "0"}
    subprocess.run(["taskkill", "/F", "/IM", image], env=environment,
                   capture_output=True, check=False)
    listing = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {image}"], env=environment,
                             capture_output=True, text=True, check=False).stdout
    if image.lower() in listing.lower():
        raise ValidationError(f"Lingering instance of {image} survived taskkill; refusing to double-start")
    process = subprocess.Popen([str(executable)], cwd=str(executable.parent))
    return {"image": image, "pid": process.pid}


def compare_archives(before, after, changed):
    """Independent check: same names, same order, only the listed entry differs."""
    if len(before.entries) != len(after.entries):
        raise ValidationError(f"Entry count changed: {len(before.entries)} -> {len(after.entries)}")
    differences = []
    for old, new in zip(before.entries, after.entries):
        if old.name != new.name:
            raise ValidationError(f"Entry order changed at {old.name!r} -> {new.name!r}")
        if old.size != new.size or sha256(before.read(old.name)) != sha256(after.read(old.name)):
            differences.append(old.name)
    expected = {name_key(changed)}
    if {name_key(name) for name in differences} != expected:
        raise ValidationError(f"Unexpected changed entries: {sorted(set(differences) - {changed})}")
    return {"entries": len(after.entries), "changed": differences}


def deploy_chapter(archive_path, entry, translated, manifest_path, backup_path,
                   expect_entries=None, dry_run=False):
    archive_path, translated = Path(archive_path), Path(translated)
    manifest_path, backup_path = Path(manifest_path), Path(backup_path)
    for path in (manifest_path, backup_path):
        if path.exists():
            raise ValidationError(f"Refusing to overwrite {path}")
    archive = Archive(archive_path)
    if expect_entries is not None and len(archive.entries) != expect_entries:
        raise ValidationError(f"Expected {expect_entries} entries, found {len(archive.entries)}")
    if name_key(entry) not in archive.by_name:
        raise ValidationError(f"Unknown ARC entry: {entry}")
    before_sha = sha256(archive.read(entry))

    manifest = {"archive_sha256": file_sha256(archive_path),
                "replacements": [{"name": entry,
                                  "file": os.path.relpath(translated, manifest_path.parent).replace("\\", "/"),
                                  "before_sha256": before_sha}]}
    if dry_run:
        return {"entry": entry, "before_sha256": before_sha, "dry_run": True}

    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    rebuilt = archive_path.with_suffix(archive_path.suffix + ".rebuild")
    if rebuilt.exists():
        raise ValidationError(f"Stale rebuild file: {rebuilt}")
    archive.rebuild({entry: translated.read_bytes()}, rebuilt)
    result = compare_archives(archive, Archive(rebuilt), entry)
    shutil.copy2(archive_path, backup_path)
    os.replace(rebuilt, archive_path)
    result.update({"entry": entry, "before_sha256": before_sha,
                   "after_sha256": sha256(Archive(archive_path).read(entry)),
                   "backup": str(backup_path), "manifest": str(manifest_path)})
    return result
