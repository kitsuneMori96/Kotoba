import json
import tempfile
import unittest
from pathlib import Path

from tools.majiro.terms import check, conflicts, ledger_violations, load_ledger, render_report


def row(script, offset, source, translation, kind="text"):
    return {"script": script, "offset": offset, "kind": kind, "source": source, "translation": translation}


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.json"

    def write(self, terms):
        self.path.write_text(json.dumps({"terms": terms}, ensure_ascii=False), encoding="utf-8")
        return load_ledger(self.path)

    def test_load_and_reject(self):
        terms = self.write({"ルリ": {"dst": "琉璃", "category": "character", "status": "confirmed"},
                            "空": {"dst": ""}})
        self.assertIn("ルリ", terms)
        self.assertNotIn("空", terms)
        self.path.write_text("[]", encoding="utf-8")
        with self.assertRaises(Exception):
            load_ledger(self.path)

    def test_exact_and_nameplate_matches(self):
        terms = self.write({"ルリ": {"dst": "琉璃", "status": "confirmed"},
                            "女の子": {"dst": "女孩", "status": "decided"}})
        rows = [row("a", 1, "ルリ", "琉璃"),
                row("a", 2, "ルリ＠収録済み", "琉璃"),
                row("a", 3, "女の子", "少女")]
        found = ledger_violations(rows, terms)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["offset"], 3)
        self.assertEqual(found[0]["severity"], "warn")

    def test_substring_is_not_a_violation(self):
        """境内 inside a sentence must not be forced to 院内."""
        terms = self.write({"境内": {"dst": "院内", "status": "confirmed"}})
        rows = [row("a", 1, "神社境内を掃除する", "打扫神社境内")]
        self.assertEqual(ledger_violations(rows, terms), [])

    def test_deprecated_terms_are_ignored(self):
        terms = self.write({"旧": {"dst": "旧译", "status": "deprecated"}})
        self.assertEqual(ledger_violations([row("a", 1, "旧", "新译")], terms), [])

    def test_conflicts_and_reverse(self):
        rows = [row("a", 1, "同じ", "相同"), row("b", 2, "同じ", "一样"),
                row("b", 3, "違う", "相同")]
        found = conflicts(rows)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["source"], "同じ")
        self.assertEqual({v["translation"] for v in found[0]["variants"]}, {"相同", "一样"})
        self.assertEqual(len([item for item in check(rows)["reverse"] if item["translation"] == "相同"]), 1)

    def test_report_renders_variants_and_recommendation(self):
        terms = self.write({"同じ": {"dst": "相同", "category": "term", "status": "confirmed"}})
        report = check([row("a", 1, "同じ", "相同"), row("b", 2, "同じ", "一样")], terms)
        text = render_report(report)
        self.assertIn("相同（1）", text)
        self.assertIn("建议", text)


if __name__ == "__main__":
    unittest.main()
