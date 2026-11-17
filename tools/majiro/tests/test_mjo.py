import copy
import os
import struct
import unittest
from unittest.mock import Mock

from tools.majiro.arc import ValidationError
from tools.majiro.mjo import ENCRYPTED, PLAIN, Script, crypt, decode_string, encode_string, export_text, import_text, verify_pair
from tools.majiro.toolchain import Toolchain


def instruction(opcode, payload=b""):
    return struct.pack("<H", opcode) + payload


def string_instruction(text, opcode=0x840, encoding="utf8"):
    payload = encode_string(text, encoding)
    return instruction(opcode, struct.pack("<H", len(payload) + 1) + payload + b"\0")


def make_mjo(code, entrypoint=0, encrypted=False, functions=None):
    functions = [(0x12345678, entrypoint)] if functions is None else functions
    return ((ENCRYPTED if encrypted else PLAIN) + struct.pack("<III", entrypoint, 0, len(functions))
            + b"".join(struct.pack("<II", *item) for item in functions)
            + struct.pack("<I", len(code)) + (crypt(code) if encrypted else code))


class MjoTests(unittest.TestCase):
    def setUp(self):
        self.code = string_instruction("Alpha") + instruction(0x841) + instruction(0x800, struct.pack("<i", 0)) + instruction(0x82B)
        self.data = make_mjo(self.code)

    def test_plain_and_encrypted(self):
        self.assertEqual(Script(self.data).shape("utf8"), Script(make_mjo(self.code, encrypted=True)).shape("utf8"))
        self.assertEqual(crypt(crypt(self.code)), self.code)

    def test_validate_malformed(self):
        for data in (b"", self.data[:31], self.data[:-1], self.data + b"x",
                     make_mjo(instruction(0xFFFF)), make_mjo(instruction(0x801, b"\0\0")),
                     make_mjo(instruction(0x840, b"\x02\0a!")), make_mjo(self.code, entrypoint=1),
                     make_mjo(self.code, functions=[(1, 0), (1, 2)]),
                     make_mjo(instruction(0x829, b"\x01\0\xff"))):
            with self.subTest(data=data[:32]), self.assertRaises(ValidationError):
                Script(data)

    def test_jump_and_switch_targets(self):
        code = instruction(0x82C, struct.pack("<i", 0)) + instruction(0x82B)
        Script(make_mjo(code))
        with self.assertRaises(ValidationError):
            Script(make_mjo(instruction(0x82C, struct.pack("<i", -5)) + instruction(0x82B)))
        code = instruction(0x850, struct.pack("<Hii", 2, 4, 0)) + instruction(0x82B)
        parsed = Script(make_mjo(code))
        self.assertEqual(parsed.instructions[0].operands, (("c", (12, 12)),))

    def test_shifted_text_preserves_topology_but_not_offsets(self):
        before_text, after_text = string_instruction("A"), string_instruction("Longer")
        before = make_mjo(instruction(0x82C, struct.pack("<i", len(before_text))) + before_text + instruction(0x82B))
        after = make_mjo(instruction(0x82C, struct.pack("<i", len(after_text))) + after_text + instruction(0x82B))
        with self.assertRaises(ValidationError):
            verify_pair(before, after, "utf8", "utf8", {6: "Longer"})
        self.assertFalse(verify_pair(before, after, "utf8", "utf8", {6: "Longer"}, False)["offsets_preserved"])

    def test_reject_nontext_changes(self):
        wrong = make_mjo(string_instruction("Alpha") + instruction(0x841) + instruction(0x800, struct.pack("<i", 1)) + instruction(0x82B))
        with self.assertRaises(ValidationError):
            verify_pair(self.data, wrong, "utf8", "utf8")

    def test_controls_roundtrip(self):
        for encoding in ("cp932", "utf8"):
            for raw in (b"abc\x81\x01", b"a\x7fb", b"abc\\quote\""):
                self.assertEqual(encode_string(decode_string(raw, encoding), encoding), raw)
        for text in ("a\nb", "\ue000", "a" * 65535, "\ud800"):
            with self.subTest(text=text[:10]), self.assertRaises(ValidationError):
                encode_string(text, "utf8")

    def test_export_only_text_or_explicit_ldstr(self):
        data = make_mjo(string_instruction("Resource", 0x801) + self.code)
        result = export_text(data, "synthetic.mjo", "utf8")
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["source"], "Alpha")
        self.assertEqual(len(export_text(data, "synthetic.mjo", "utf8", [0])["records"]), 2)
        with self.assertRaises(ValidationError):
            export_text(data, "synthetic.mjo", "utf8", [1])

    def test_noop_is_identical_without_toolchain(self):
        document = export_text(self.data, "synthetic.mjo", "utf8")
        output, report = import_text(self.data, document, "synthetic.mjo", "utf8", "utf8", None)
        self.assertEqual(output, self.data)
        self.assertEqual(report["old_saves"], "unchanged_bytes")

    def test_reject_exchange_identity_and_record_tampering(self):
        original = export_text(self.data, "synthetic.mjo", "utf8")
        cases = []
        for field, value in (("script", "other.mjo"), ("source_sha256", "bad"), ("encoding", "cp932")):
            changed = copy.deepcopy(original)
            changed[field] = value
            cases.append(changed)
        for field, value in (("id", "bad"), ("source", "bad"), ("offset", 1), ("kind", "ldstr")):
            changed = copy.deepcopy(original)
            changed["records"][0][field] = value
            cases.append(changed)
        changed = copy.deepcopy(original)
        changed["records"].append(changed["records"][0])
        cases.append(changed)
        for document in cases:
            with self.subTest(document=document), self.assertRaises(ValidationError):
                import_text(self.data, document, "synthetic.mjo", "utf8", "utf8", None)

    def test_missing_control_marker_refused(self):
        data = make_mjo(string_instruction("A\ue081\ue001") + instruction(0x82B))
        document = export_text(data, "synthetic.mjo", "utf8")
        document["records"][0]["translation"] = "B"
        with self.assertRaises(ValidationError):
            import_text(data, document, "synthetic.mjo", "utf8", "utf8", None)

    def test_import_checked_against_bytecode(self):
        document = export_text(self.data, "synthetic.mjo", "utf8")
        document["records"][0]["translation"] = "Bravo"
        output = make_mjo(self.code.replace(b"Alpha", b"Bravo"))
        tool = Mock()
        tool.disassemble.side_effect = ['  text "Alpha"\n  proc\n  ldc.i 0\n  ret\n', '  text "Bravo"\n  proc\n  ldc.i 0\n  ret\n']
        tool.assemble.side_effect = [self.data, output, output]
        result, report = import_text(self.data, document, "synthetic.mjo", "utf8", "utf8", tool)
        self.assertEqual(result, output)
        self.assertTrue(report["offsets_preserved"])
        self.assertEqual(report["old_saves"], "not_runtime_tested")
        self.assertIn('text "Bravo"', tool.assemble.call_args_list[1].args[0])


@unittest.skipUnless(os.environ.get("MAJIRO_TEST_TOOLCHAIN"), "explicit local maji path not supplied")
class MjoToolchainIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.toolchain = Toolchain(os.environ["MAJIRO_TEST_TOOLCHAIN"])
        cls.toolchain.verify()

    def setUp(self):
        self.script_name = "synthetic.mjo"
        self.source_text = "テスト\ue081\ue001"
        # Synthetic function with a conditional jump across the editable text.
        prologue = (instruction(0x836, struct.pack("<H", 0))
                    + instruction(0x829, struct.pack("<H", 0))
                    + instruction(0x800, struct.pack("<i", 0)))
        body = string_instruction(self.source_text, encoding="cp932") + instruction(0x841)
        branch = instruction(0x82D, struct.pack("<i", len(body)))
        self.text_offset = len(prologue) + len(branch)
        self.code = prologue + branch + body + instruction(0x800, struct.pack("<i", 0)) + instruction(0x82B)
        self.data = make_mjo(self.code)
        self.document = export_text(self.data, self.script_name, "cp932")
        self.assertEqual(len(self.document["records"]), 1)
        self.assertEqual(self.document["records"][0]["source"], self.source_text)
        self.assertEqual(self.document["records"][0]["offset"], self.text_offset)

    def assert_imported_text(self, output, report, translation, offsets_preserved):
        before, after = Script(self.data), Script(output)
        self.assertEqual(before.shape("cp932", {self.text_offset: translation}), after.shape("utf8"))
        exported = export_text(output, self.script_name, "utf8")
        self.assertEqual(exported["records"][0]["source"], translation)
        text = next(item for item in after.instructions if item.opcode == 0x840)
        self.assertEqual(text.operands, (("s", translation[:-2].encode("utf8") + b"\x81\x01"),))
        self.assertTrue(report["structure_verified"])
        self.assertEqual(report["offsets_preserved"], offsets_preserved)
        self.assertEqual(report["changed_strings"], 1)
        self.assertEqual(report["old_saves"], "not_runtime_tested")

    def test_cp932_to_utf8_length_change_refused_by_default(self):
        self.document["records"][0]["translation"] = "中文测试\ue081\ue001"
        with self.assertRaisesRegex(ValidationError, "MJO instruction offsets changed"):
            import_text(self.data, self.document, self.script_name, "cp932", "utf8", self.toolchain)

    def test_cp932_to_utf8_length_change_preserves_structure_when_allowed(self):
        translation = "中文测试\ue081\ue001"
        self.document["records"][0]["translation"] = translation
        output, report = import_text(self.data, self.document, self.script_name, "cp932", "utf8",
                                     self.toolchain, preserve_offsets=False)
        self.assert_imported_text(output, report, translation, offsets_preserved=False)
        before, after = Script(self.data), Script(output)
        delta = len(encode_string(translation, "utf8")) - len(encode_string(self.source_text, "cp932"))
        self.assertGreater(delta, 0)
        self.assertEqual(len(output) - len(self.data), delta)
        old_jump = next(item for item in before.instructions if item.opcode == 0x82D)
        new_jump = next(item for item in after.instructions if item.opcode == 0x82D)
        old_target, new_target = old_jump.operands[0][1], new_jump.operands[0][1]
        self.assertEqual(new_target - old_target, delta)
        self.assertEqual(before.offsets[old_target], after.offsets[new_target])

    def test_cp932_to_utf8_same_byte_length_preserves_offsets(self):
        translation = "中文\ue081\ue001"
        self.assertEqual(len(encode_string(self.source_text, "cp932")), len(encode_string(translation, "utf8")))
        self.document["records"][0]["translation"] = translation
        output, report = import_text(self.data, self.document, self.script_name, "cp932", "utf8", self.toolchain)
        self.assert_imported_text(output, report, translation, offsets_preserved=True)
        before, after = Script(self.data), Script(output)
        self.assertEqual([(item.offset, item.end) for item in before.instructions],
                         [(item.offset, item.end) for item in after.instructions])
        self.assertEqual(before.entrypoint, after.entrypoint)
        self.assertEqual(before.functions, after.functions)
        self.assertEqual(len(output), len(self.data))
        self.assertNotEqual(output, self.data)

    def test_no_changes_return_original_bytes(self):
        for encrypted in (False, True):
            for translation in (None, self.source_text):
                for target_encoding in ("cp932", "utf8"):
                    with self.subTest(encrypted=encrypted, translation=translation, target_encoding=target_encoding):
                        data = make_mjo(self.code, encrypted=encrypted)
                        document = export_text(data, self.script_name, "cp932")
                        document["records"][0]["translation"] = translation
                        output, report = import_text(data, document, self.script_name, "cp932",
                                                     target_encoding, self.toolchain)
                        self.assertEqual(output, data)
                        self.assertEqual(report, {"structure_verified": True, "offsets_preserved": True,
                                                  "old_saves": "unchanged_bytes", "changed_strings": 0})


if __name__ == "__main__":
    unittest.main()
