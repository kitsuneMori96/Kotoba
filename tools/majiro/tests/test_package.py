import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.majiro import package
from tools.majiro.arc import HEADER, MAGIC, ValidationError, file_sha256
from tools.majiro.audit import audit
from tools.majiro.tests.test_arc import make_arc, script


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.target = self.base / "target"
        self.inputs = self.base / "inputs"
        self.output = self.base / "package"
        self.target.mkdir()
        self.inputs.mkdir()
        self.spec_path = self.inputs / "spec.json"
        self.before = {"game.exe": b"synthetic executable v1", "winmm.dll": b"old proxy",
                       "winmm_orig.dll": b"ordinary dependency stub, not a system DLL",
                       "data.arc": b"accepted resource base", "data2.arc": b"second resource",
                       "fastdata.arc": b"third resource", "notes.txt": b"unrelated",
                       "save/slot01.sav": b"synthetic save data", "game.cfg": b"synthetic config"}
        empty_arc = HEADER.pack(MAGIC, 0, HEADER.size, HEADER.size)
        self.before.update({"scenario.arc": empty_arc, "update.arc": empty_arc})
        for name, data in self.before.items():
            path = self.target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.process_check = package._assert_not_running
        self.runtime = self.enterContext(mock.patch.object(package, "_assert_not_running"))

    def write_json(self, path, value):
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def spec(self, paths=("winmm.dll", "data.arc")):
        value = {"schema": 1, "executable": {"path": "game.exe", "sha256": digest(self.before["game.exe"])},
                 "files": []}
        for i, name in enumerate(paths):
            source = self.inputs / f"source-{i}.bin"
            content = f"synthetic patch {i}".encode()
            if name.casefold().endswith(".arc"):
                content = make_arc([("synthetic.bin", content)])
            elif name.casefold().endswith(".mjo"):
                content = script(content)
            source.write_bytes(content)
            current = self.target / name
            value["files"].append({"path": name, "source": source.name,
                                   "before_sha256": file_sha256(current) if current.is_file() else None,
                                   "reason": "explicitly approved synthetic replacement"})
        return value

    def add_script_archive(self, spec):
        entries = [(item["path"].removeprefix("scenario/"), (self.inputs / item["source"]).read_bytes())
                   for item in spec["files"] if item["path"].startswith("scenario/")]
        (self.inputs / "scripts.arc").write_bytes(make_arc(entries))
        spec["files"].append({"path": "update.arc", "source": "scripts.arc",
                              "before_sha256": file_sha256(self.target / "update.arc"),
                              "reason": "Keep synthetic loose scripts and archive consistent"})

    def add_audit(self, spec):
        loose = []
        folder = self.target / "scenario"
        if folder.exists():
            for path in folder.rglob("*.mjo"):
                loose.append({"name": path.name,
                              "loose": {"file": path.relative_to(self.target).as_posix(),
                                        "sha256": file_sha256(path)}})
        value = {"schema": 1, "safe_to_build": True, "target": str(self.target),
                 "executable": {"file": "game.exe", "original_sha256": digest(self.before["game.exe"]),
                                "target_sha256": digest(self.before["game.exe"])},
                 "target_archives": [{"file": name, "sha256": file_sha256(self.target / name), "entries": 0}
                                     for name in ("scenario.arc", "update.arc")],
                 "scripts": loose}
        self.write_json(self.inputs / "audit.json", value)
        spec["audit"] = "audit.json"
        return value

    def build(self, spec=None):
        spec = self.spec() if spec is None else spec
        self.write_json(self.spec_path, spec)
        return package.build(self.spec_path, self.target, self.output)

    def manifest(self):
        return json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))

    def journal(self):
        return json.loads((self.target / ".ruri-state/journal.json").read_text(encoding="utf-8"))

    def assert_unrelated(self):
        for name in ("notes.txt", "save/slot01.sav", "game.cfg", "game.exe", "winmm_orig.dll"):
            self.assertEqual((self.target / name).read_bytes(), self.before[name])

    def assert_original(self):
        for name, content in self.before.items():
            self.assertEqual((self.target / name).read_bytes(), content, name)

    def assert_installed(self, manifest):
        for item in manifest["files"]:
            self.assertEqual(file_sha256(self.target / item["path"]), item["after_sha256"])

    def symlink(self, link, source, directory=False):
        try:
            link.symlink_to(source, target_is_directory=directory)
        except OSError as exc:
            self.skipTest(f"Symlink creation is unavailable: {exc}")

    def test_build_verify_install_rollback_retains_backups(self):
        manifest = self.build()
        self.assert_original()
        self.assertFalse((self.target / ".ruri-state").exists())
        self.assertEqual(manifest["files"][0]["payload"], "payload/000000.bin")
        self.assertEqual(package.verify(self.output, self.target)["status"], "verified")
        self.runtime.assert_not_called()
        self.assertEqual(package.install(self.output, self.target)["status"], "installed")
        self.assert_installed(manifest)
        self.assert_unrelated()
        self.assertEqual(package.rollback(self.target)["status"], "rolled_back")
        self.assert_original()
        self.assertEqual(package.recover(self.target)["status"], "rolled_back")
        self.assertEqual(package.rollback(self.target)["status"], "rolled_back")
        self.assertEqual((self.target / ".ruri-state/backups/000000.bin").read_bytes(), self.before["winmm.dll"])
        self.assertTrue((self.target / ".ruri-state/lock").is_file())

    def test_resource_packages_need_no_script_audit(self):
        self.build(self.spec(("data.arc", "data2.arc", "fastdata.arc")))
        package.install(self.output, self.target)
        package.rollback(self.target)
        self.assert_original()

    def test_new_loose_script_and_proxy_rollback(self):
        (self.target / "winmm.dll").unlink()
        self.before.pop("winmm.dll")
        spec = self.spec(("winmm.dll", "scenario/new/sub/test.mjo"))
        self.add_script_archive(spec)
        self.add_audit(spec)
        manifest = self.build(spec)
        package.install(self.output, self.target)
        self.assert_installed(manifest)
        package.rollback(self.target)
        self.assertFalse((self.target / "winmm.dll").exists())
        self.assertFalse((self.target / "scenario/new/sub/test.mjo").exists())
        self.assertTrue((self.target / "scenario/new/sub").is_dir())
        self.assert_original()
        package.recover(self.target)

    def test_existing_loose_script(self):
        folder = self.target / "scenario"
        folder.mkdir()
        (folder / "a.mjo").write_bytes(b"old synthetic script")
        spec = self.spec(("scenario/a.mjo",))
        self.add_script_archive(spec)
        self.add_audit(spec)
        self.build(spec)
        package.install(self.output, self.target)
        package.rollback(self.target)
        self.assertEqual((folder / "a.mjo").read_bytes(), b"old synthetic script")

    def test_real_audit_output_contract(self):
        original = self.base / "original"
        original.mkdir()
        for name in ("game.exe", "scenario.arc", "update.arc"):
            shutil.copyfile(self.target / name, original / name)
        result = audit(original, self.target, "game.exe")
        self.assertTrue(result["safe_to_build"])
        self.write_json(self.inputs / "audit.json", result)
        spec = self.spec(("scenario.arc",))
        spec["audit"] = "audit.json"
        self.build(spec)
        package.verify(self.output, self.target)

    def test_update_only_target_contract_and_late_base_archive(self):
        original = self.base / "original"
        original.mkdir()
        for name in ("game.exe", "scenario.arc", "update.arc"):
            shutil.copyfile(self.target / name, original / name)
        (self.target / "scenario.arc").unlink()
        result = audit(original, self.target, "game.exe")
        self.assertTrue(result["safe_to_build"])
        self.write_json(self.inputs / "audit.json", result)
        spec = self.spec(("update.arc",))
        spec["audit"] = "audit.json"
        self.build(spec)
        package.verify(self.output, self.target)
        (self.target / "scenario.arc").write_bytes(self.before["scenario.arc"])
        with self.assertRaisesRegex(ValidationError, "Incomplete target archive audit"):
            package.verify(self.output, self.target)

    def test_invalid_payload_structure_rejected(self):
        for name in ("data.arc", "scenario.arc", "scenario/new.mjo"):
            with self.subTest(name=name):
                spec = self.spec((name,))
                self.add_audit(spec)
                (self.inputs / spec["files"][0]["source"]).write_bytes(b"invalid structure")
                with self.assertRaises(ValidationError):
                    self.build(spec)
                self.assertFalse(self.output.exists())

    def test_new_payload_cannot_create_loose_archive_conflict(self):
        spec = self.spec(("scenario/new.mjo",))
        self.add_script_archive(spec)
        self.add_audit(spec)
        (self.inputs / "scripts.arc").write_bytes(make_arc([("new.mjo", script(b"different"))]))
        with self.assertRaisesRegex(ValidationError, "loose/archive conflict"):
            self.build(spec)
        self.assertFalse(self.output.exists())

    def test_new_archive_cannot_remove_audited_script(self):
        original = self.base / "original"
        original.mkdir()
        (self.target / "update.arc").write_bytes(make_arc([("keep.mjo", script(b"keep"))]))
        for name in ("game.exe", "scenario.arc", "update.arc"):
            shutil.copyfile(self.target / name, original / name)
        document = audit(original, self.target, "game.exe")
        self.write_json(self.inputs / "audit.json", document)
        spec = self.spec(("update.arc",))
        spec["audit"] = "audit.json"
        with self.assertRaisesRegex(ValidationError, "removes previously audited"):
            self.build(spec)
        self.assertFalse(self.output.exists())

    def test_rehashed_invalid_payload_rejected_by_verify(self):
        self.build()
        payload = self.output / "payload/000001.bin"
        payload.write_bytes(b"invalid archive")
        manifest = self.manifest()
        manifest["files"][1]["after_sha256"] = file_sha256(payload)
        manifest["files"][1]["size"] = payload.stat().st_size
        self.write_json(self.output / "manifest.json", manifest)
        with self.assertRaises(ValidationError):
            package.verify(self.output, self.target)
        self.assertFalse((self.target / ".ruri-state").exists())

    def test_script_updates_require_successful_audit(self):
        for name in ("scenario.arc", "update.arc", "scenario/new.mjo"):
            with self.subTest(name=name):
                spec = self.spec((name,))
                with self.assertRaises(ValidationError):
                    self.build(spec)
                self.assertFalse(self.output.exists())
                document = self.add_audit(spec)
                document["safe_to_build"] = False
                self.write_json(self.inputs / "audit.json", document)
                with self.assertRaises(ValidationError):
                    self.build(spec)
                self.assertFalse(self.output.exists())

    def test_audit_binding_rejects_stale_and_incomplete_evidence(self):
        spec = self.spec(("scenario.arc",))
        document = self.add_audit(spec)
        variants = []
        for key, value in (("target", str(self.inputs)), ("safe_to_build", 1),
                           ("target_archives", []), ("scripts", None)):
            changed = copy.deepcopy(document)
            changed[key] = value
            variants.append(changed)
        for field in ("original_sha256", "target_sha256", "file"):
            changed = copy.deepcopy(document)
            changed["executable"][field] = "0" * 64 if "sha256" in field else "other.exe"
            variants.append(changed)
        changed = copy.deepcopy(document)
        changed["target_archives"][1]["sha256"] = "0" * 64
        variants.append(changed)
        changed = copy.deepcopy(document)
        changed["target_archives"][1] = changed["target_archives"][0]
        variants.append(changed)
        for index, changed in enumerate(variants):
            with self.subTest(index=index):
                self.write_json(self.inputs / "audit.json", changed)
                with self.assertRaises(ValidationError):
                    self.build(spec)
                self.assertFalse(self.output.exists())

    def test_loose_audit_checks_hash_and_exact_inventory(self):
        folder = self.target / "scenario"
        folder.mkdir()
        first = folder / "a.mjo"
        first.write_bytes(b"first")
        spec = self.spec(("scenario.arc",))
        self.add_audit(spec)
        for mode in ("changed", "added", "removed"):
            with self.subTest(mode=mode):
                first.write_bytes(b"first")
                extra = folder / "b.mjo"
                extra.unlink(missing_ok=True)
                if mode == "changed":
                    first.write_bytes(b"changed")
                elif mode == "added":
                    extra.write_bytes(b"extra")
                else:
                    first.unlink()
                with self.assertRaises(ValidationError):
                    self.build(spec)
                self.assertFalse(self.output.exists())

    def test_verify_and_install_recheck_embedded_audit(self):
        spec = self.spec(("scenario.arc",))
        self.add_audit(spec)
        self.build(spec)
        (self.target / "scenario").mkdir()
        (self.target / "scenario/external.mjo").write_bytes(b"late loose override")
        for operation in (package.verify, package.install):
            with self.assertRaises(ValidationError):
                operation(self.output, self.target)
        self.assertFalse((self.target / ".ruri-state").exists())

    def test_dangerous_disallowed_and_duplicate_spec_paths(self):
        names = ["../winmm.dll", "/winmm.dll", "C:/winmm.dll", "winmm.dll:stream", "CON",
                 "winmm_orig.dll", "game.exe", "game.cfg", "save/test.mjo", "other/test.mjo",
                 "scenario/../test.mjo", "scenario/NUL.mjo", "scenario/a.mjo.", "scenario/a.mjo "]
        for name in names:
            with self.subTest(name=name):
                spec = self.spec(("winmm.dll",))
                spec["files"][0]["path"] = name
                with self.assertRaises(ValidationError):
                    self.build(spec)
                self.assertFalse(self.output.exists())
        for names in (("winmm.dll", "WINMM.DLL"), ("scenario/a.mjo", "scenario/A.MJO/b.mjo")):
            spec = self.spec(("winmm.dll", "data.arc"))
            for item, name in zip(spec["files"], names):
                item["path"] = name
            with self.assertRaises(ValidationError):
                self.build(spec)

    def test_resource_null_digest_and_empty_reason_rejected(self):
        for field, value in (("before_sha256", None), ("reason", "  "), ("before_sha256", "approximate")):
            spec = self.spec(("data.arc",))
            spec["files"][0][field] = value
            with self.assertRaises(ValidationError):
                self.build(spec)

    def test_host_and_before_mismatch_during_build(self):
        for field in ("host", "before"):
            spec = self.spec()
            if field == "host":
                spec["executable"]["sha256"] = "0" * 64
            else:
                spec["files"][0]["before_sha256"] = "0" * 64
            with self.assertRaises(ValidationError):
                self.build(spec)
        self.assert_original()

    def test_existing_output_and_output_inside_target_rejected(self):
        self.build()
        marker = self.output / "marker"
        marker.write_bytes(b"preserve")
        with self.assertRaises(ValidationError):
            self.build()
        self.assertEqual(marker.read_bytes(), b"preserve")
        with self.assertRaises(ValidationError):
            package.build(self.spec_path, self.target, self.target / "forbidden")
        self.assertFalse((self.target / "forbidden").exists())

    def test_target_must_be_existing_ordinary_directory(self):
        self.write_json(self.spec_path, self.spec())
        for target in (self.base / "absent", self.target / "game.exe"):
            with self.assertRaises((ValidationError, OSError)):
                package.build(self.spec_path, target, self.output)
        self.assertFalse(self.output.exists())

    def test_absolute_source_and_audit_paths(self):
        spec = self.spec(("scenario.arc",))
        self.add_audit(spec)
        spec["files"][0]["source"] = str(self.inputs / spec["files"][0]["source"])
        spec["audit"] = str(self.inputs / "audit.json")
        self.build(spec)
        package.verify(self.output, self.target)

    def test_original_dll_cannot_be_a_payload_source(self):
        spec = self.spec(("winmm.dll",))
        spec["files"][0]["source"] = str(self.target / "winmm_orig.dll")
        with self.assertRaises(ValidationError):
            self.build(spec)

    def test_duplicate_json_keys_rejected(self):
        self.spec_path.write_text('{"schema":1,"schema":1}', encoding="utf-8")
        with self.assertRaises(ValidationError):
            package.build(self.spec_path, self.target, self.output)
        self.build()
        (self.output / "manifest.json").write_text('{"schema":1,"schema":1}', encoding="utf-8")
        with self.assertRaises(ValidationError):
            package.verify(self.output, self.target)

    def test_bad_manifest_fields_paths_digests_and_sizes(self):
        self.build()
        original = self.manifest()
        variants = []
        for field, value in (("schema", True), ("schema", 2), ("files", []), ("files", None)):
            changed = copy.deepcopy(original)
            changed[field] = value
            variants.append(changed)
        for field, value in (("path", "../winmm.dll"), ("path", "winmm_orig.dll"),
                             ("payload", "../outside.bin"), ("payload", "payload/000001.bin"),
                             ("after_sha256", "x" * 64), ("before_sha256", "0" * 63),
                             ("size", True), ("size", -1), ("size", 999), ("reason", "")):
            changed = copy.deepcopy(original)
            changed["files"][0][field] = value
            variants.append(changed)
        changed = copy.deepcopy(original)
        changed["files"][1]["path"] = "WINMM.DLL"
        variants.append(changed)
        changed = copy.deepcopy(original)
        changed["files"][0]["path"] = "scenario/a.mjo"
        changed["files"][1]["path"] = "scenario/A.mjo/b.mjo"
        variants.append(changed)
        changed = copy.deepcopy(original)
        changed["executable"]["unexpected"] = True
        variants.append(changed)
        changed = copy.deepcopy(original)
        del changed["files"][0]["reason"]
        variants.append(changed)
        for index, value in enumerate(variants):
            with self.subTest(index=index):
                self.write_json(self.output / "manifest.json", value)
                with self.assertRaises(ValidationError):
                    package.verify(self.output, self.target)
        self.assert_original()

    def test_corrupt_payload_rejected_before_state_creation(self):
        self.build()
        (self.output / "payload/000001.bin").write_bytes(b"corrupt")
        with self.assertRaises(ValidationError):
            package.install(self.output, self.target)
        self.assertFalse((self.target / ".ruri-state").exists())
        self.assert_original()

    def test_install_rechecks_executable_and_target_before_state(self):
        self.build()
        for name in ("game.exe", "data.arc"):
            with self.subTest(name=name):
                (self.target / name).write_bytes(b"external version")
                with self.assertRaises(ValidationError):
                    package.install(self.output, self.target)
                self.assertFalse((self.target / ".ruri-state").exists())
                (self.target / name).write_bytes(self.before[name])

    def test_second_verification_under_lock(self):
        self.build()
        real = package._verified
        calls = 0

        def verify_again(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                (self.output / "payload/000001.bin").write_bytes(b"changed between checks")
            return real(*args)

        with mock.patch.object(package, "_verified", side_effect=verify_again):
            with self.assertRaises(ValidationError):
                package.install(self.output, self.target)
        self.assertEqual(calls, 2)
        self.assert_original()
        package.recover(self.target)
        package.recover(self.target)
        self.assert_original()

    def test_missing_dependency_stops_install(self):
        self.build()
        (self.target / "winmm_orig.dll").unlink()
        with self.assertRaises(OSError):
            package.install(self.output, self.target)
        self.assertFalse((self.target / ".ruri-state").exists())

    def test_refuse_running_target_and_process_check_failure(self):
        self.build()
        for message in ("Target executable is running", "Cannot enumerate running processes"):
            self.runtime.side_effect = ValidationError(message)
            with self.assertRaises(ValidationError):
                package.install(self.output, self.target)
            self.assertFalse((self.target / ".ruri-state").exists())
        self.runtime.side_effect = None
        manifest = self.manifest()
        package.install(self.output, self.target)
        self.runtime.side_effect = ValidationError("running")
        for operation in (package.rollback, package.recover):
            with self.assertRaises(ValidationError):
                operation(self.target)
            self.assert_installed(manifest)

    def test_insufficient_space_before_install_and_rollback(self):
        self.build()
        with mock.patch.object(package.shutil, "disk_usage", return_value=SimpleNamespace(free=0)):
            with self.assertRaises(ValidationError):
                package.install(self.output, self.target)
        self.assertFalse((self.target / ".ruri-state").exists())
        package.install(self.output, self.target)
        with mock.patch.object(package.shutil, "disk_usage", return_value=SimpleNamespace(free=0)):
            with self.assertRaises(ValidationError):
                package.rollback(self.target)
        self.assert_installed(self.manifest())

    def test_insufficient_space_build_creates_nothing(self):
        with mock.patch.object(package.shutil, "disk_usage", return_value=SimpleNamespace(free=0)):
            with self.assertRaises(ValidationError):
                self.build()
        self.assertFalse(self.output.exists())

    def test_existing_state_directory_and_file_preserved(self):
        self.build()
        state = self.target / ".ruri-state"
        state.mkdir()
        marker = state / "user-owned"
        marker.write_bytes(b"keep")
        with self.assertRaises(ValidationError):
            package.install(self.output, self.target)
        self.assertEqual(marker.read_bytes(), b"keep")
        marker.unlink()
        state.rmdir()
        state.write_bytes(b"same-name file")
        with self.assertRaises(ValidationError):
            package.install(self.output, self.target)
        self.assertEqual(state.read_bytes(), b"same-name file")

    def test_second_install_and_retired_state_are_refused(self):
        self.build()
        package.install(self.output, self.target)
        with self.assertRaises(ValidationError):
            package.install(self.output, self.target)
        package.rollback(self.target)
        with self.assertRaises(ValidationError):
            package.install(self.output, self.target)
        self.assert_original()

    def test_state_lock_exclusive(self):
        self.build()
        package.install(self.output, self.target)
        with package._lock(self.target / ".ruri-state"):
            with self.assertRaises(ValidationError):
                package.rollback(self.target)
        self.assert_installed(self.manifest())
        package.rollback(self.target)

    def test_half_install_failure_recover_and_idempotence(self):
        manifest = self.build()
        real_replace = package.os.replace

        def fail_second(source, destination):
            if Path(destination) == self.target / "data.arc":
                raise OSError("synthetic replacement interruption")
            return real_replace(source, destination)

        with mock.patch.object(package.os, "replace", side_effect=fail_second):
            with self.assertRaises(OSError):
                package.install(self.output, self.target)
        self.assertEqual(file_sha256(self.target / "winmm.dll"), manifest["files"][0]["after_sha256"])
        self.assertEqual((self.target / "data.arc").read_bytes(), self.before["data.arc"])
        self.assertEqual(self.journal()["status"], "installing")
        with self.assertRaises(ValidationError):
            package.rollback(self.target)
        self.assertEqual(package.recover(self.target)["status"], "rolled_back")
        self.assert_original()
        package.recover(self.target)
        self.assert_original()
        self.assertFalse(list(self.target.glob(".ruri-*.tmp")))

    def test_recover_uses_hash_not_stale_progress(self):
        self.build()
        real_replace = package.os.replace

        def replaced_but_not_journaled(source, destination):
            result = real_replace(source, destination)
            if Path(destination) == self.target / "winmm.dll":
                raise OSError("interruption after replacing, before journaling")
            return result

        with mock.patch.object(package.os, "replace", side_effect=replaced_but_not_journaled):
            with self.assertRaises(OSError):
                package.install(self.output, self.target)
        self.assertEqual(self.journal()["files"][0]["state"], "backed_up")
        package.recover(self.target)
        self.assert_original()

    def test_interrupted_backup_preparation_is_recoverable(self):
        self.build()
        real_copy = package._copy_new

        def stop_before_second_backup(source, destination, expected):
            if Path(destination) == self.target / ".ruri-state/backups/000001.bin":
                raise OSError("synthetic stop before backup")
            return real_copy(source, destination, expected)

        with mock.patch.object(package, "_copy_new", side_effect=stop_before_second_backup):
            with self.assertRaises(OSError):
                package.install(self.output, self.target)
        self.assert_original()
        self.assertEqual(self.journal()["status"], "preparing")
        package.recover(self.target)
        package.recover(self.target)
        self.assert_original()

    def test_interrupted_rollback_can_be_recovered(self):
        self.build()
        package.install(self.output, self.target)
        real_replace = package.os.replace

        def stop_second(source, destination):
            if Path(destination) == self.target / "data.arc":
                raise OSError("synthetic rollback interruption")
            return real_replace(source, destination)

        with mock.patch.object(package.os, "replace", side_effect=stop_second):
            with self.assertRaises(OSError):
                package.rollback(self.target)
        self.assertEqual(self.journal()["status"], "recovering")
        package.recover(self.target)
        package.recover(self.target)
        self.assert_original()

    def test_recovery_can_clean_owned_incomplete_temporary_only(self):
        self.build()
        real_copy = package._copy_new

        def partial_temporary(source, destination, expected):
            if Path(destination).parent == self.target and Path(destination).name.endswith(".tmp"):
                Path(destination).write_bytes(b"partial")
                raise OSError("interrupted write")
            return real_copy(source, destination, expected)

        with mock.patch.object(package, "_copy_new", side_effect=partial_temporary):
            with self.assertRaises(OSError):
                package.install(self.output, self.target)
        unrelated = self.target / ".ruri-unrelated.tmp"
        unrelated.write_bytes(b"user-owned")
        package.recover(self.target)
        self.assertEqual(unrelated.read_bytes(), b"user-owned")
        self.assertEqual(list(self.target.glob(".ruri-*.tmp")), [unrelated])
        self.assert_original()

    def test_later_external_modification_blocks_entire_rollback_and_recover(self):
        manifest = self.build()
        package.install(self.output, self.target)
        (self.target / "data.arc").write_bytes(b"user modification")
        journal_path = self.target / ".ruri-state/journal.json"
        original_journal = journal_path.read_bytes()
        for operation in (package.rollback, package.recover):
            with self.assertRaises(ValidationError):
                operation(self.target)
            self.assertEqual(file_sha256(self.target / "winmm.dll"), manifest["files"][0]["after_sha256"])
            self.assertEqual((self.target / "data.arc").read_bytes(), b"user modification")
            self.assertEqual(journal_path.read_bytes(), original_journal)
        self.assert_unrelated()

    def test_later_corrupt_backup_blocks_all_changes(self):
        manifest = self.build()
        package.install(self.output, self.target)
        (self.target / ".ruri-state/backups/000001.bin").write_bytes(b"damaged backup")
        for operation in (package.rollback, package.recover):
            with self.assertRaises(ValidationError):
                operation(self.target)
            self.assert_installed(manifest)

    def test_missing_backup_blocks_all_changes(self):
        manifest = self.build()
        package.install(self.output, self.target)
        (self.target / ".ruri-state/backups/000001.bin").unlink()
        with self.assertRaises(ValidationError):
            package.rollback(self.target)
        self.assert_installed(manifest)

    def test_changed_new_file_is_not_deleted(self):
        spec = self.spec(("scenario/new.mjo",))
        self.add_script_archive(spec)
        self.add_audit(spec)
        self.build(spec)
        package.install(self.output, self.target)
        (self.target / "scenario/new.mjo").write_bytes(b"user content")
        with self.assertRaises(ValidationError):
            package.rollback(self.target)
        self.assertEqual((self.target / "scenario/new.mjo").read_bytes(), b"user content")

    def test_deleted_existing_file_blocks_rollback(self):
        manifest = self.build()
        package.install(self.output, self.target)
        (self.target / "data.arc").unlink()
        with self.assertRaises(ValidationError):
            package.rollback(self.target)
        self.assertEqual(file_sha256(self.target / "winmm.dll"), manifest["files"][0]["after_sha256"])

    def test_no_transaction_recovery_is_idempotent_and_readonly(self):
        for _ in range(2):
            self.assertEqual(package.recover(self.target)["status"], "no_transaction")
        self.assertFalse((self.target / ".ruri-state").exists())
        self.assert_original()

    def test_unrecognized_or_dangerous_state_is_not_modified(self):
        manifest = self.build()
        package.install(self.output, self.target)
        original = self.journal()
        for field, value in (("backup", "../game.exe"), ("path", "winmm_orig.dll"), ("state", "anything")):
            changed = copy.deepcopy(original)
            changed["files"][0][field] = value
            self.write_json(self.target / ".ruri-state/journal.json", changed)
            with self.assertRaises(ValidationError):
                package.recover(self.target)
            self.assert_installed(manifest)
        self.write_json(self.target / ".ruri-state/journal.json", original)
        (self.target / ".ruri-state/lock").write_bytes(b"unknown lock")
        with self.assertRaises(ValidationError):
            package.recover(self.target)
        self.assert_installed(manifest)

    def test_target_hardlinks_are_broken_without_mutating_aliases(self):
        aliases = {}
        for name in ("winmm.dll", "data.arc"):
            alias = self.base / f"external-{name}"
            os.link(self.target / name, alias)
            aliases[name] = alias
        self.build()
        package.install(self.output, self.target)
        for name, alias in aliases.items():
            self.assertEqual(alias.read_bytes(), self.before[name])
            self.assertNotEqual(alias.stat().st_ino, (self.target / name).stat().st_ino)
        package.rollback(self.target)
        self.assert_original()
        for name, alias in aliases.items():
            self.assertEqual(alias.read_bytes(), self.before[name])

    def test_hardlinked_backup_is_rejected(self):
        manifest = self.build()
        package.install(self.output, self.target)
        os.link(self.target / ".ruri-state/backups/000001.bin", self.base / "backup-alias")
        with self.assertRaises(ValidationError):
            package.rollback(self.target)
        self.assert_installed(manifest)

    def test_target_symlink_and_dangling_symlink_rejected(self):
        self.build()
        target = self.target / "data.arc"
        target.unlink()
        external = self.base / "external.arc"
        external.write_bytes(self.before["data.arc"])
        self.symlink(target, external)
        with self.assertRaises(ValidationError):
            package.install(self.output, self.target)
        self.assertEqual(external.read_bytes(), self.before["data.arc"])
        target.unlink()
        self.symlink(target, self.base / "missing.arc")
        with self.assertRaises(ValidationError):
            package.install(self.output, self.target)

    def test_package_payload_symlink_rejected(self):
        self.build()
        payload = self.output / "payload/000000.bin"
        external = self.base / "external-payload"
        payload.rename(external)
        self.symlink(payload, external)
        with self.assertRaises(ValidationError):
            package.verify(self.output, self.target)

    def test_source_symlink_rejected(self):
        spec = self.spec()
        source = self.inputs / spec["files"][0]["source"]
        source.unlink()
        self.symlink(source, self.target / "notes.txt")
        with self.assertRaises(ValidationError):
            self.build(spec)
        self.assertFalse(self.output.exists())

    def test_root_and_ancestor_directory_links_rejected(self):
        self.build()
        linked = self.base / "linked-target"
        self.symlink(linked, self.target, directory=True)
        with self.assertRaises(ValidationError):
            package.install(self.output, linked)
        outer = self.base / "linked-ancestor"
        self.symlink(outer, self.base, directory=True)
        with self.assertRaises(ValidationError):
            package.verify(self.output, outer / "target")

    def test_scenario_directory_link_rejected(self):
        outside = self.base / "external-scenario"
        outside.mkdir()
        self.symlink(self.target / "scenario", outside, directory=True)
        spec = self.spec(("scenario/new.mjo",))
        self.add_audit(spec)
        with self.assertRaises(ValidationError):
            self.build(spec)
        self.assertEqual(list(outside.iterdir()), [])

    def test_mock_reparse_root_rejected(self):
        self.build()
        real = Path.lstat
        root = self.target

        def lstat(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            if path == root:
                return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
            return info

        with mock.patch.object(Path, "lstat", lstat):
            with self.assertRaises(ValidationError):
                package.install(self.output, self.target)

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_windows_junction_ancestor_rejected(self):
        self.build()
        junction = self.base / "junction"
        subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(self.base)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with self.assertRaises(ValidationError):
                package.install(self.output, junction / "target")
        finally:
            junction.rmdir()

    def test_state_symlink_rejected(self):
        self.build()
        external = self.base / "external-state"
        external.mkdir()
        self.symlink(self.target / ".ruri-state", external, directory=True)
        with self.assertRaises(ValidationError):
            package.install(self.output, self.target)
        with self.assertRaises(ValidationError):
            package.recover(self.target)
        self.assertEqual(list(external.iterdir()), [])

    def test_recovery_rechecks_linked_later_destination_before_writes(self):
        manifest = self.build()
        package.install(self.output, self.target)
        external = self.base / "external.arc"
        (self.target / "data.arc").rename(external)
        self.symlink(self.target / "data.arc", external)
        with self.assertRaises(ValidationError):
            package.rollback(self.target)
        self.assertEqual(file_sha256(self.target / "winmm.dll"), manifest["files"][0]["after_sha256"])

    def test_input_paths_are_relative_to_spec_parent(self):
        spec = self.spec(("winmm.dll",))
        source = self.base / "outside-input.bin"
        source.write_bytes(b"synthetic payload outside spec directory")
        spec["files"][0]["source"] = "../outside-input.bin"
        self.build(spec)
        self.assertEqual((self.output / "payload/000000.bin").read_bytes(), source.read_bytes())

    def test_output_alias_inside_target_is_rejected(self):
        self.write_json(self.spec_path, self.spec())
        aliased_output = self.target.resolve() / "must-not-create"
        with self.assertRaises(ValidationError):
            package.build(self.spec_path, self.target, aliased_output)
        self.assertFalse(aliased_output.exists())

    def test_external_change_during_temporary_copy_is_not_overwritten(self):
        self.build()
        real_copy = package._copy_new

        def change_during_copy(source, destination, expected):
            result = real_copy(source, destination, expected)
            if Path(destination).parent == self.target and Path(destination).name.endswith(".tmp"):
                (self.target / "winmm.dll").write_bytes(b"user edit during copy")
            return result

        with mock.patch.object(package, "_copy_new", side_effect=change_during_copy):
            with self.assertRaises(ValidationError):
                package.install(self.output, self.target)
        self.assertEqual((self.target / "winmm.dll").read_bytes(), b"user edit during copy")
        self.assertEqual((self.target / "data.arc").read_bytes(), self.before["data.arc"])
        with self.assertRaises(ValidationError):
            package.recover(self.target)

    @unittest.skipUnless(os.name == "nt", "Native Windows process enumeration")
    def test_native_process_check_detects_current_python(self):
        import sys
        with self.assertRaisesRegex(ValidationError, "Target executable is running"):
            self.process_check(Path(sys.executable))
        self.process_check(self.target / "game.exe")

    def fake_process_api(self, image, basename="game.exe"):
        api = mock.MagicMock()
        api.CreateToolhelp32Snapshot.return_value = 123
        api.OpenProcess.return_value = 124
        api.CloseHandle.return_value = True
        api.Process32NextW.return_value = False

        def short_name(path, buffer, size):
            buffer.value = str(self.target / "GAMEAL~1.EXE")
            return len(buffer.value)

        def first(snapshot, entry):
            entry._obj.name = basename
            entry._obj.pid = 42
            return True

        def query(handle, flags, buffer, size):
            buffer.value = str(image)
            return True

        api.GetShortPathNameW.side_effect = short_name
        api.Process32FirstW.side_effect = first
        api.QueryFullProcessImageNameW.side_effect = query
        return api

    @unittest.skipUnless(os.name == "nt", "Win32 process API test")
    def test_process_check_compares_full_paths_and_short_aliases(self):
        other = self.inputs / "game.exe"
        other.write_bytes(b"unrelated executable stub")
        for image, basename, running in ((other, "game.exe", False),
                                          (self.target / "game.exe", "game.exe", True),
                                          (self.target / "game.exe", "GAMEAL~1.EXE", True)):
            with self.subTest(image=image, basename=basename):
                api = self.fake_process_api(image, basename)
                with mock.patch.object(package.ctypes, "WinDLL", return_value=api), \
                        mock.patch.object(package.ctypes, "get_last_error", return_value=18):
                    if running:
                        with self.assertRaises(ValidationError):
                            self.process_check(self.target / "game.exe")
                    else:
                        self.process_check(self.target / "game.exe")
                self.assertEqual(api.CloseHandle.call_count, 2)

    @unittest.skipUnless(os.name == "nt", "Win32 process API test")
    def test_process_api_errors_fail_closed(self):
        for failure in ("snapshot", "access", "query", "enumeration", "alias"):
            with self.subTest(failure=failure):
                api = self.fake_process_api(self.inputs / "game.exe")
                if failure == "snapshot":
                    api.CreateToolhelp32Snapshot.return_value = package.ctypes.c_void_p(-1).value
                elif failure == "access":
                    api.OpenProcess.return_value = 0
                elif failure == "query":
                    api.QueryFullProcessImageNameW.side_effect = None
                    api.QueryFullProcessImageNameW.return_value = 0
                elif failure == "alias":
                    api.GetShortPathNameW.side_effect = None
                    api.GetShortPathNameW.return_value = 0
                with mock.patch.object(package.ctypes, "WinDLL", return_value=api), \
                        mock.patch.object(package.ctypes, "get_last_error", return_value=5 if failure == "enumeration" else 18):
                    with self.assertRaises(ValidationError):
                        self.process_check(self.target / "game.exe")

    def test_case_alias_existing_target_resolves_to_one_file(self):
        (self.target / "winmm.dll").rename(self.target / "WINMM.DLL")
        spec = self.spec(("data.arc",))
        spec["files"][0].update(path="winmm.dll", before_sha256=digest(self.before["winmm.dll"]))
        self.build(spec)
        package.install(self.output, self.target)
        package.rollback(self.target)
        self.assertEqual((self.target / "WINMM.DLL").read_bytes(), self.before["winmm.dll"])
        self.assertEqual(sum(path.name.casefold() == "winmm.dll" for path in self.target.iterdir()), 1)


if __name__ == "__main__":
    unittest.main()
