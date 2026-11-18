import json
import tempfile
import unittest
from pathlib import Path

from tools.majiro.dupcheck import apply_reuse, duplicate_report


def exchange(script, pairs, filled=True):
    records = [{"id": f"{script}-{i}", "offset": i * 10, "kind": kind, "source": source,
                "translation": translation if filled else None}
               for i, (kind, source, translation) in enumerate(pairs)]
    return {"script": script, "records": records}


class DupcheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def write(self, name, document):
        path = self.dir / name
        path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        return path

    def test_identical_sequence_is_flagged_as_duplicate_copy(self):
        done = exchange("route00", [("text", "あ", "甲"), ("text", "い", "乙"), ("ldstr", "う", "丙")])
        twin = exchange("shibetsu01",
                        [(r["kind"], r["source"], None) for r in done["records"]])
        self.write("route00.pristine.exchange.json", done)
        pending = self.write("shibetsu01.pristine.exchange.json", twin)
        report = duplicate_report(pending, self.dir)
        self.assertEqual(report["reused"], 3)
        self.assertEqual(report["untranslated"], 0)
        self.assertEqual(report["identical_to"], "route00.pristine.exchange.json")
        self.assertIn("duplicate script copy", report["verdict"])

    def test_partial_overlap_still_needs_review(self):
        self.write("done.pristine.exchange.json", exchange("done", [("text", "あ", "甲")]))
        pending = self.write("new.pristine.exchange.json",
                             exchange("new", [("text", "あ", None), ("text", "い", None)]))
        report = duplicate_report(pending, self.dir)
        self.assertEqual((report["reused"], report["untranslated"]), (1, 1))
        self.assertFalse(report["identical_to"])
        self.assertIn("review each", report["verdict"])

    def test_unfilled_and_self_exchanges_are_not_sources(self):
        self.write("half.pristine.exchange.json",
                   exchange("half", [("text", "あ", None)], filled=False))
        pending = self.write("new.pristine.exchange.json", exchange("new", [("text", "あ", None)]))
        report = duplicate_report(pending, self.dir)
        self.assertEqual(report["reused"], 0)
        self.assertIn("from scratch", report["verdict"])

    def test_apply_reuse_writes_contiguous_batches_without_touching_exchange(self):
        self.write("done.pristine.exchange.json",
                   exchange("done", [("text", "あ", "甲"), ("text", "う", "丙")]))
        pending = self.write("new.pristine.exchange.json",
                             exchange("new", [("text", "あ", None), ("text", "い", None), ("text", "う", None)]))
        result = apply_reuse(pending, self.dir)
        self.assertEqual(result["reusable"], 2)
        batches = [json.loads(Path(c).read_text(encoding="utf-8"))["translations"] for c in result["commits"]]
        self.assertEqual([b[0]["id"] for b in batches], [0, 2])       # ids 0 and 2 are not one run
        self.assertTrue(all(json.loads(pending.read_text(encoding="utf-8"))["records"][i]["translation"] is None
                            for i in range(3)))                       # the exchange is filled by apply_commit, not here


if __name__ == "__main__":
    unittest.main()
