import json
import tempfile
import unittest
from pathlib import Path

from tools.majiro.corpus import exchange_files, rows_from, write_all


def exchange(script, records, encoding="utf8"):
    return {"schema": 1, "script": script, "source_sha256": "0" * 64, "encoding": encoding,
            "records": records}


def record(offset, source, translation, kind="text"):
    return {"id": f"id{offset}", "offset": offset, "kind": kind,
            "source": source, "translation": translation}


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "a.exchange.json").write_text(
            json.dumps(exchange("01ルリエロルート05", [record(1, "おはよう", "早上好")]), ensure_ascii=False),
            encoding="utf-8")
        (self.root / "b.pristine.exchange.json").write_text(
            json.dumps(exchange("00プロローグ02.mjo", [record(1, "おはよう", "早安"),
                                                       record(2, "　", "")]), ensure_ascii=False),
            encoding="utf-8")
        self.ledger = self.root / "ledger.json"
        self.ledger.write_text(json.dumps({"terms": {"おはよう": {"dst": "早上好", "status": "confirmed",
                                                                  "category": "greeting"}}},
                                          ensure_ascii=False), encoding="utf-8")

    def test_script_names_are_normalised(self):
        names = [entry["script"] for entry in exchange_files(self.root)]
        self.assertEqual(names, ["00プロローグ02", "01ルリエロルート05"])

    def test_pristine_export_wins_over_short_name(self):
        (self.root / "b.exchange.json").write_text(
            json.dumps(exchange("00プロローグ02", [record(1, "おはよう", None)]), ensure_ascii=False),
            encoding="utf-8")
        names = [entry["script"] for entry in exchange_files(self.root)]
        self.assertEqual(names.count("00プロローグ02"), 1)

    def test_write_all_outputs(self):
        result = write_all(self.root, self.ledger)
        self.assertEqual(len(result["rows"]), 3)
        tsv = (self.root / "语料-已译全量.tsv").read_text(encoding="utf-8").splitlines()
        self.assertEqual(tsv[0], "章\tkind\tid\toffset\t日文源\t中文译")
        self.assertEqual(len(tsv), 4)
        table = (self.root / "术语总表.md").read_text(encoding="utf-8")
        self.assertIn("共 1 条", table)
        self.assertIn("| おはよう | 早上好 |", table)
        self.assertIn("译名一致性报告", (self.root / "译名一致性报告.md").read_text(encoding="utf-8"))
        index = (self.root / "语料索引.md").read_text(encoding="utf-8")
        self.assertIn("| 01ルリエロルート05 | 1 | 1 | — |", index)

    def test_conflict_surfaces(self):
        result = write_all(self.root, self.ledger)
        self.assertEqual(result["report"]["summary"]["conflicts"], 1)
        self.assertEqual(result["report"]["summary"]["violations"], 1)


if __name__ == "__main__":
    unittest.main()
