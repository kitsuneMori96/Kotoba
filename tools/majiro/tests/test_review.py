import unittest

from tools.majiro.arc import ValidationError
from tools.majiro.review import build_review, ldstr_offsets_of
from tools.majiro.tests.test_mjo import instruction, make_mjo, string_instruction


def script(*texts):
    return make_mjo(b"".join(string_instruction(text) for text in texts) + instruction(0x82B))


class ReviewTests(unittest.TestCase):
    def test_pairs_source_and_shipped_text_by_position(self):
        text = build_review(script("Alpha", "Beta"), script("阿尔法", "贝塔"),
                            "test", "utf8", "utf8", [], "标题")
        self.assertIn("日: Alpha", text)
        self.assertIn("中: 阿尔法", text)
        self.assertLess(text.index("日: Alpha"), text.index("日: Beta"))
        self.assertEqual(text.count("] text @"), 2)

    def test_reads_shipped_bytes_not_a_preview(self):
        """A translation that never reached the MJO must show up as the original."""
        text = build_review(script("Alpha"), script("Alpha"), "test", "utf8", "utf8", [], "标题")
        self.assertIn("中: Alpha", text)

    def test_kind_or_count_drift_is_rejected(self):
        with self.assertRaises(ValidationError):
            build_review(script("Alpha"), script("阿尔法", "贝塔"), "test", "utf8", "utf8", [], "标题")
        with self.assertRaises(ValidationError):
            build_review(script("Alpha"), make_mjo(string_instruction("阿尔法", opcode=0x801) + instruction(0x82B)),
                         "test", "utf8", "utf8", [0], "标题")

    def test_ldstr_offsets_are_collected(self):
        document = {"records": [{"offset": 1, "kind": "text"}, {"offset": 9, "kind": "ldstr"}]}
        self.assertEqual(ldstr_offsets_of(document), [9])

    def test_ldstr_offset_shift_after_import_is_mapped(self):
        """Translated strings change length, so shipped ldstr offsets differ from source ones."""
        from tools.majiro.mjo import Script
        pristine = make_mjo(string_instruction("Alpha") + string_instruction("Choice", opcode=0x801)
                            + instruction(0x82B))
        shipped = make_mjo(string_instruction("阿尔法阿尔法") + string_instruction("选项", opcode=0x801)
                           + instruction(0x82B))
        source_ldstr = [item.offset for item in Script(pristine).instructions if item.opcode == 0x801]
        shipped_ldstr = [item.offset for item in Script(shipped).instructions if item.opcode == 0x801]
        self.assertNotEqual(source_ldstr, shipped_ldstr)
        text = build_review(pristine, shipped, "test", "utf8", "utf8", source_ldstr, "标题")
        self.assertIn("日: Choice", text)
        self.assertIn("中: 选项", text)
        self.assertEqual(text.count("] ldstr @"), 1)


if __name__ == "__main__":
    unittest.main()
