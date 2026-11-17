import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.majiro.__main__ import main
from tools.majiro.arc import Archive, file_sha256, sha256
from tools.majiro.tests.test_arc import make_arc, script


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main([str(arg) for arg in args])

    def test_export_and_verify(self):
        source, output = self.root / "test.mjo", self.root / "text.json"
        source.write_bytes(script(b"Synthetic text"))
        self.assertEqual(self.invoke(["verify-mjo", source]), 0)
        self.assertEqual(self.invoke(["export", source, "--encoding", "utf8", "--out", output]), 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf8"))["records"][0]["source"], "Synthetic text")
        self.assertEqual(self.invoke(["export", source, "--encoding", "utf8", "--out", output]), 1)

    def test_rebuild_manifest(self):
        source = self.root / "source.arc"
        source.write_bytes(make_arc([("one.mjo", b"old"), ("two.bin", b"unchanged")]))
        (self.root / "payload.bin").write_bytes(b"new")
        manifest = self.root / "replace.json"
        document = {"archive_sha256": file_sha256(source), "replacements": [
            {"name": "one.mjo", "before_sha256": sha256(b"old"), "file": "payload.bin"}]}
        manifest.write_text(json.dumps(document), encoding="utf8")
        output = self.root / "output.arc"
        self.assertEqual(self.invoke(["rebuild-arc", source, "--manifest", manifest, "--out", output]), 0)
        self.assertEqual(Archive(output).read("one.mjo"), b"new")
        self.assertEqual(Archive(output).read("two.bin"), b"unchanged")
        self.assertEqual(Archive(source).read("one.mjo"), b"old")
        document["archive_sha256"] = "wrong"
        manifest.write_text(json.dumps(document), encoding="utf8")
        self.assertEqual(self.invoke(["rebuild-arc", source, "--manifest", manifest, "--out", self.root / "refused.arc"]), 1)
        self.assertFalse((self.root / "refused.arc").exists())

    def test_failed_audit_still_emits_report_with_nonzero_exit(self):
        original, target = self.root / "original", self.root / "target"
        for folder in (original, target):
            folder.mkdir()
            (folder / "game.exe").write_bytes(b"same-exe")
            (folder / "scenario.arc").write_bytes(make_arc([("one.mjo", script(b"old"))]))
            (folder / "update.arc").write_bytes(make_arc([("one.mjo", script(b"official"))]))
        (target / "scenario").mkdir()
        (target / "scenario/one.mjo").write_bytes(script(b"old"))
        output = self.root / "audit.json"
        result = self.invoke(["audit", "--original", original, "--target", target, "--exe", "game.exe", "--out", output])
        self.assertEqual(result, 2)
        self.assertFalse(json.loads(output.read_text(encoding="utf8"))["safe_to_build"])

    def test_invalid_script_is_not_accepted_as_identical(self):
        original, target = self.root / "original", self.root / "target"
        for folder in (original, target):
            folder.mkdir()
            (folder / "game.exe").write_bytes(b"same-exe")
            for name in ("scenario.arc", "update.arc"):
                (folder / name).write_bytes(make_arc([("one.mjo", b"not-bytecode")]))
        output = self.root / "audit.json"
        self.assertEqual(self.invoke(["audit", "--original", original, "--target", target, "--exe", "game.exe", "--out", output]), 2)
        document = json.loads(output.read_text(encoding="utf8"))
        self.assertIn("invalid_target_mjo", document["scripts"][0]["issues"])

    def test_package_install_dry_run_and_rollback(self):
        target = self.root / "target"
        target.mkdir()
        for name, content in (("host.exe", b"synthetic host"), ("winmm.dll", b"before"),
                              ("winmm_orig.dll", b"synthetic dependency"), ("save.dat", b"unchanged")):
            (target / name).write_bytes(content)
        source = self.root / "payload.dll"
        source.write_bytes(b"after")
        spec = self.root / "spec.json"
        spec.write_text(json.dumps({"schema": 1, "executable": {"path": "host.exe", "sha256": file_sha256(target / "host.exe")},
                                   "files": [{"path": "winmm.dll", "source": "payload.dll", "before_sha256": sha256(b"before"),
                                              "reason": "synthetic CLI installation"}]}), encoding="utf8")
        package = self.root / "package"
        self.assertEqual(self.invoke(["build", "--spec", spec, "--target", target, "--out", package]), 0)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["install", str(package), "--target", str(target), "--dry-run"]), 0)
        plan = json.loads(stdout.getvalue())["plan"]
        self.assertEqual([item["path"] for item in plan], ["winmm.dll"])
        self.assertFalse((target / ".kotoba-state").exists())
        self.assertEqual((target / "winmm.dll").read_bytes(), b"before")
        from unittest.mock import patch
        with patch("tools.majiro.package._assert_not_running"):
            self.assertEqual(self.invoke(["install", package, "--target", target]), 0)
            self.assertEqual((target / "winmm.dll").read_bytes(), b"after")
            self.assertEqual(self.invoke(["rollback", "--target", target]), 0)
            self.assertEqual(self.invoke(["recover", "--target", target]), 0)
        self.assertEqual((target / "winmm.dll").read_bytes(), b"before")
        self.assertEqual((target / "save.dat").read_bytes(), b"unchanged")

    def test_bad_input_returns_nonzero(self):
        self.assertEqual(self.invoke(["verify-arc", self.root / "missing.arc"]), 1)
        source = self.root / "invalid.mjo"
        source.write_bytes(b"not-an-mjo")
        self.assertEqual(self.invoke(["verify-mjo", source]), 1)


if __name__ == "__main__":
    unittest.main()
