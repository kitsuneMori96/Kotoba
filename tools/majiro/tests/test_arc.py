import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from tools.majiro.arc import Archive, HEADER, INDEX, MAGIC, ValidationError, safe_name, sha256
from tools.majiro.audit import audit, load_json
from tools.majiro.tests.test_mjo import make_mjo, string_instruction, instruction


def script(data):
    return make_mjo(string_instruction(data.decode("ascii")) + instruction(0x82B))


def make_arc(items):
    names = b"".join(name.encode("cp932") + b"\0" for name, _ in items)
    names_offset = HEADER.size + len(items) * INDEX.size
    offset = names_offset + len(names)
    table = []
    for key, (_, data) in enumerate(items, 1):
        table.append(INDEX.pack(key, offset, len(data)))
        offset += len(data)
    return HEADER.pack(MAGIC, len(items), names_offset, names_offset + len(names)) + b"".join(table) + names + b"".join(data for _, data in items)


class ArcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "source.arc"
        self.data = make_arc([("alpha.mjo", b"old"), ("beta.mjo", b"unchanged"), ("empty.bin", b"")])
        self.path.write_bytes(self.data)

    def invalid(self, data):
        self.path.write_bytes(data)
        with self.assertRaises(ValidationError):
            Archive(self.path)

    def test_roundtrip_and_replace(self):
        arc = Archive(self.path)
        output = self.root / "new.arc"
        arc.rebuild({"ALPHA.MJO": b"longer-new"}, output)
        rebuilt = Archive(output)
        self.assertEqual(rebuilt.read("alpha.mjo"), b"longer-new")
        self.assertEqual(rebuilt.read("beta.mjo"), b"unchanged")
        self.assertEqual(rebuilt.read("empty.bin"), b"")
        self.assertEqual(self.path.read_bytes(), self.data)
        self.assertEqual([e.key for e in arc.entries], [e.key for e in rebuilt.entries])
        noop = self.root / "noop.arc"
        arc.rebuild({}, noop)
        self.assertEqual(noop.read_bytes(), self.data)

    def test_refuse_output_overwrite_and_unknown(self):
        arc = Archive(self.path)
        with self.assertRaises(ValidationError):
            arc.rebuild({}, self.path)
        with self.assertRaises(ValidationError):
            arc.rebuild({"unknown": b"a"}, self.root / "new.arc")

    def test_reject_truncation(self):
        for length in (0, 15, 27, 30, len(self.data) - 1):
            with self.subTest(length=length):
                self.invalid(self.data[:length])

    def test_bad_header_and_bounds(self):
        for offset, value in ((0, 0), (16, 0xFFFFFFFF), (20, 0), (24, 0xFFFFFFFF), (36, 0), (40, 0xFFFFFFFF)):
            data = bytearray(self.data)
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset):
                self.invalid(data)

    def test_overlaps_duplicates_and_terminator(self):
        data = bytearray(self.data)
        struct.pack_into("<I", data, 52, struct.unpack_from("<I", data, 36)[0])
        self.invalid(data)
        data = bytearray(self.data)
        struct.pack_into("<Q", data, 44, 1)
        self.invalid(data)
        self.invalid(make_arc([("a.mjo", b"a"), ("A.MJO", b"b")]))
        data = bytearray(self.data)
        data_offset = struct.unpack_from("<I", data, 24)[0]
        data[data_offset - 1] = 1
        self.invalid(data)

    def test_bad_cp932_and_paths(self):
        self.invalid(make_arc([("../bad.mjo", b"a")]))
        data = bytearray(make_arc([("a", b"a")]))
        data[HEADER.size + INDEX.size] = 0x81
        self.invalid(data)
        for path in ("../x", "a/../b", "a\\..\\b", "/tmp/x", "C:x", "a:b", "NUL.txt", "COM¹", "a.", "a/", "a\x00b", "a//b"):
            with self.subTest(path=path), self.assertRaises(ValidationError):
                safe_name(path)
        self.assertEqual(safe_name("folder\\normal.bin"), "folder/normal.bin")

    def test_cp932_trailing_backslash_byte(self):
        self.path.write_bytes(make_arc([("ソ.mjo", b"ok")]))
        self.assertEqual(Archive(self.path).read("ソ.mjo"), b"ok")

    def test_source_changed(self):
        arc = Archive(self.path)
        self.path.write_bytes(self.data + b"changed")
        with self.assertRaises(ValidationError):
            arc.read("alpha.mjo")

    def test_hardlink_source_never_written(self):
        link = self.root / "linked.arc"
        os.link(self.path, link)
        Archive(self.path).rebuild({"alpha.mjo": b"changed"}, self.root / "new.arc")
        self.assertEqual(link.read_bytes(), self.data)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original, self.target = self.root / "original", self.root / "target"
        for folder in (self.original, self.target):
            folder.mkdir()
            (folder / "game.exe").write_bytes(b"synthetic-executable")
            (folder / "scenario.arc").write_bytes(make_arc([("a.mjo", script(b"old-placeholder"))]))
            (folder / "update.arc").write_bytes(make_arc([("a.mjo", script(b"official-update")), ("b.mjo", script(b"new-script"))]))
        (self.target / "scenario").mkdir()

    def run_audit(self, allowlist=None):
        return audit(self.original, self.target, "game.exe", allowlist)

    def test_official_update_wins(self):
        result = self.run_audit()
        self.assertTrue(result["safe_to_build"])
        self.assertEqual(result["scripts"][0]["official"]["selected"]["sha256"], sha256(script(b"official-update")))

    def test_target_can_use_a_complete_update_archive_without_base(self):
        (self.target / "scenario.arc").unlink()
        self.assertTrue(self.run_audit()["safe_to_build"])

    def test_loose_conflict_blocks_without_writes(self):
        loose = self.target / "scenario/a.mjo"
        loose.write_bytes(script(b"old-placeholder"))
        result = self.run_audit()
        self.assertFalse(result["safe_to_build"])
        self.assertIn("loose_archive_conflict", result["scripts"][0]["issues"])
        self.assertEqual(loose.read_bytes(), script(b"old-placeholder"))

    def test_allowlist_is_exact_and_does_not_hide_loose_conflict(self):
        (self.target / "update.arc").write_bytes(make_arc([("a.mjo", script(b"reviewed-change")), ("b.mjo", script(b"new-script"))]))
        change = {"name": "a.mjo", "base_sha256": sha256(script(b"official-update")),
                  "sha256": sha256(script(b"reviewed-change")), "reason": "synthetic reviewed fix"}
        path = self.root / "allow.json"
        path.write_text(json.dumps({"schema": 1, "changes": [change]}), encoding="utf-8")
        self.assertTrue(self.run_audit(path)["safe_to_build"])
        (self.target / "scenario/a.mjo").write_bytes(b"wrong")
        self.assertFalse(self.run_audit(path)["safe_to_build"])
        change["base_sha256"] = sha256(script(b"old-placeholder"))
        path.write_text(json.dumps({"schema": 1, "changes": [change]}), encoding="utf-8")
        self.assertFalse(self.run_audit(path)["safe_to_build"])

    def test_missing_extra_and_executable(self):
        (self.target / "update.arc").write_bytes(make_arc([("extra.mjo", b"not-approved")]))
        (self.target / "game.exe").write_bytes(b"unknown-version")
        result = self.run_audit()
        self.assertFalse(result["safe_to_build"])
        self.assertGreaterEqual(result["counts"]["unresolved"], 3)

    def test_duplicate_json_keys(self):
        path = self.root / "bad.json"
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaises(ValidationError):
            load_json(path)


if __name__ == "__main__":
    unittest.main()
