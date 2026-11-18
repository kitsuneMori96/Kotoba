import json
import tempfile
import unittest
from pathlib import Path

from tools.majiro.arc import Archive, ValidationError, sha256
from tools.majiro.deploy import compare_archives, deploy_chapter
from tools.majiro.tests.test_arc import make_arc


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.arc = self.root / "update.arc"
        self.arc.write_bytes(make_arc([("a.mjo", b"old-a"), ("b.mjo", b"old-b"), ("c.bin", b"keep")]))
        self.zh = self.root / "a.zh.mjo"
        self.zh.write_bytes(b"new-a-longer")
        self.manifest = self.root / "deploy-a.json"
        self.backup = self.root / "update.arc.before"

    def test_deploy_replaces_one_entry_and_keeps_backup(self):
        result = deploy_chapter(self.arc, "a.mjo", self.zh, self.manifest, self.backup, expect_entries=3)
        self.assertEqual(result["changed"], ["a.mjo"])
        self.assertEqual(Archive(self.arc).read("a.mjo"), b"new-a-longer")
        self.assertEqual(Archive(self.arc).read("b.mjo"), b"old-b")
        self.assertEqual(Archive(self.backup).read("a.mjo"), b"old-a")
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(manifest["replacements"][0]["before_sha256"], sha256(b"old-a"))
        self.assertEqual(manifest["replacements"][0]["file"], os_relpath(self.zh, self.manifest.parent))
        self.assertFalse(self.arc.with_suffix(".arc.rebuild").exists())

    def test_refuses_stale_inputs(self):
        with self.assertRaises(ValidationError):
            deploy_chapter(self.arc, "missing.mjo", self.zh, self.manifest, self.backup)
        with self.assertRaises(ValidationError):
            deploy_chapter(self.arc, "a.mjo", self.zh, self.manifest, self.backup, expect_entries=4)
        self.backup.write_bytes(b"occupied")
        with self.assertRaises(ValidationError):
            deploy_chapter(self.arc, "a.mjo", self.zh, self.manifest, self.backup)
        self.assertEqual(Archive(self.arc).read("a.mjo"), b"old-a")

    def test_dry_run_changes_nothing(self):
        result = deploy_chapter(self.arc, "a.mjo", self.zh, self.manifest, self.backup, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertFalse(self.manifest.exists())
        self.assertEqual(Archive(self.arc).read("a.mjo"), b"old-a")

    def test_compare_archives_detects_unexpected_change(self):
        other = self.root / "other.arc"
        Archive(self.arc).rebuild({"b.mjo": b"secretly-changed"}, other)
        with self.assertRaises(ValidationError):
            compare_archives(Archive(self.arc), Archive(other), "a.mjo")


def os_relpath(path, start):
    import os
    return os.path.relpath(path, start).replace("\\", "/")


if __name__ == "__main__":
    unittest.main()
