import codecs
import re
import struct
from dataclasses import dataclass

from .arc import ValidationError, safe_name, sha256

PLAIN = b"MajiroObjV1.000\0"
ENCRYPTED = b"MajiroObjX1.000\0"


def _encodings():
    result = {}
    for base, count in ((0x100, 2), (0x108, 2), (0x110, 1), (0x118, 3), (0x120, 2),
                        (0x128, 1), (0x130, 1), (0x138, 3), (0x140, 3), (0x148, 3),
                        (0x150, 3), (0x158, 6), (0x160, 6), (0x168, 1), (0x170, 1),
                        (0x178, 1), (0x180, 1), (0x188, 1)):
        result.update((base + index, "") for index in range(count))
    for start in (0x1B0, 0x210, 0x270, 0x2D0):
        for index, count in enumerate((6 if start < 0x270 else 3, 2, 2, 1, 3, 2, 1, 1, 1, 1, 1)):
            result.update((start + index * 8 + kind, "fho") for kind in range(count))
    result.update((op, "") for op in (0x190, 0x191, 0x198, 0x1A0, 0x1A1, 0x1A8, 0x1A9,
                                    0x82B, 0x82F, 0x83E, 0x83F, 0x841, 0x844, 0x846))
    result.update((op, "j") for op in (0x82C, 0x82D, 0x82E, 0x830, 0x831, 0x832, 0x833,
                                     0x838, 0x839, 0x83B, 0x83C, 0x83D, 0x843, 0x845, 0x847))
    result.update({0x800: "i", 0x801: "s", 0x802: "fho", 0x803: "r", 0x80F: "h0a",
                   0x810: "h0a", 0x829: "t", 0x834: "ha", 0x835: "ha", 0x836: "t",
                   0x837: "fho", 0x83A: "l", 0x840: "s", 0x842: "s", 0x850: "c"})
    return result


ENCODINGS = _encodings()


def crypt(data):
    key = bytearray()
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
        key.extend(struct.pack("<I", value))
    return bytes(value ^ key[index & 1023] for index, value in enumerate(data))


def _raw_bytes(exc):
    return "".join(chr(0xE000 + byte) for byte in exc.object[exc.start:exc.end]), exc.end


codecs.register_error("kotoba_raw_bytes", _raw_bytes)


def codec(encoding):
    if encoding not in ("cp932", "utf8"):
        raise ValidationError("Encoding must be cp932 or utf8")
    return "utf-8" if encoding == "utf8" else "cp932"


def decode_string(data, encoding):
    text = data.decode(codec(encoding), errors="kotoba_raw_bytes")
    return "".join(chr(0xE000 + ord(c)) if ord(c) < 32 or ord(c) == 127 else c for c in text)


def encode_string(text, encoding):
    if not isinstance(text, str) or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValidationError("Literal control characters are not allowed; preserve the exported markers")
    try:
        data = b"".join(bytes([ord(c) - 0xE000]) if 0xE000 <= ord(c) <= 0xE0FF else c.encode(codec(encoding)) for c in text)
    except UnicodeEncodeError as exc:
        raise ValidationError("String cannot be represented in the selected encoding") from exc
    if b"\0" in data or len(data) > 65534:
        raise ValidationError("Embedded NUL or overlong MJO string")
    return data


def markers(text):
    return [c for c in text if 0xE000 <= ord(c) <= 0xE0FF]


@dataclass(frozen=True)
class Instruction:
    offset: int
    end: int
    opcode: int
    operands: tuple


class Script:
    def __init__(self, data):
        if len(data) < 32 or data[:16] not in (PLAIN, ENCRYPTED):
            raise ValidationError("Invalid MJO signature or truncated header")
        entrypoint, self.readmark, count = struct.unpack_from("<III", data, 16)
        code_offset = 32 + count * 8
        if count > 1_000_000 or code_offset > len(data):
            raise ValidationError("Invalid MJO function table")
        code_size = struct.unpack_from("<I", data, code_offset - 4)[0]
        if code_size != len(data) - code_offset:
            raise ValidationError("MJO bytecode length mismatch")
        functions = list(struct.iter_unpack("<II", data[28:code_offset - 4]))
        if len({key for key, _ in functions}) != count:
            raise ValidationError("Duplicate MJO function hash")
        code = data[code_offset:]
        if data[:16] == ENCRYPTED:
            code = crypt(code)
        position = 0

        def take(size):
            nonlocal position
            if size < 0 or size > len(code) - position:
                raise ValidationError("Truncated MJO instruction")
            value = code[position:position + size]
            position += size
            return value

        def u16():
            return struct.unpack("<H", take(2))[0]

        instructions = []
        while position < len(code):
            offset, opcode = position, u16()
            if opcode not in ENCODINGS:
                raise ValidationError(f"Unknown MJO opcode 0x{opcode:04x} at 0x{offset:x}")
            operands = []
            for kind in ENCODINGS[opcode]:
                if kind == "s":
                    size = u16()
                    value = take(size)
                    if not size or value[-1] != 0 or b"\0" in value[:-1]:
                        raise ValidationError("Invalid MJO string terminator")
                    value = value[:-1]
                elif kind == "t":
                    value = take(u16())
                    if any(item > 5 for item in value):
                        raise ValidationError("Invalid MJO type list")
                elif kind == "j":
                    delta = struct.unpack("<i", take(4))[0]
                    value = position + delta
                elif kind == "c":
                    targets = []
                    for _ in range(u16()):
                        delta = struct.unpack("<i", take(4))[0]
                        targets.append(position + delta)
                    value = tuple(targets)
                else:
                    value = take(2 if kind in "foal" else 4)
                    if kind == "0" and value != bytes(4):
                        raise ValidationError("Nonzero MJO call placeholder")
                operands.append((kind, value))
            instructions.append(Instruction(offset, position, opcode, tuple(operands)))
        offsets = {item.offset: index for index, item in enumerate(instructions)}
        if entrypoint not in offsets or any(offset not in offsets for _, offset in functions):
            raise ValidationError("MJO entrypoint is not an instruction boundary")
        if entrypoint not in {offset for _, offset in functions}:
            raise ValidationError("MJO entrypoint is absent from function table")
        for item in instructions:
            for kind, value in item.operands:
                if kind in ("j", "c"):
                    if any(target not in offsets for target in ((value,) if kind == "j" else value)):
                        raise ValidationError("MJO jump target is not an instruction boundary")
        self.data, self.instructions, self.offsets = data, tuple(instructions), offsets
        self.functions, self.entrypoint = tuple(functions), entrypoint

    def shape(self, encoding, replacements=None):
        replacements = replacements or {}
        result = []
        for item in self.instructions:
            operands = []
            for kind, value in item.operands:
                if kind == "s":
                    value = replacements.get(item.offset, decode_string(value, encoding))
                elif kind == "j":
                    value = self.offsets[value]
                elif kind == "c":
                    value = tuple(self.offsets[target] for target in value)
                operands.append((kind, value))
            result.append((item.opcode, tuple(operands)))
        functions = tuple((key, self.offsets[offset]) for key, offset in self.functions)
        return self.readmark, self.offsets[self.entrypoint], functions, tuple(result)


def verify_pair(before, after, source_encoding, target_encoding, replacements=None, preserve_offsets=True):
    source, target = Script(before), Script(after)
    if source.shape(source_encoding, replacements) != target.shape(target_encoding):
        raise ValidationError("MJO changed instructions, control flow, references, or unapproved strings")
    same_offsets = (tuple((i.offset, i.end) for i in source.instructions) == tuple((i.offset, i.end) for i in target.instructions)
                    and source.functions == target.functions and source.entrypoint == target.entrypoint)
    if preserve_offsets and not same_offsets:
        raise ValidationError("MJO instruction offsets changed; old-save compatibility mode refuses this output")
    return {"structure_verified": True, "offsets_preserved": same_offsets, "old_saves": "not_runtime_tested"}


def export_text(data, script_name, encoding, ldstr_offsets=()):
    script_name = safe_name(script_name)
    script = Script(data)
    allowed = set(ldstr_offsets)
    if any(type(offset) is not int or offset not in script.offsets or script.instructions[script.offsets[offset]].opcode != 0x801 for offset in allowed):
        raise ValidationError("An explicit text allowlist offset does not point to ldstr")
    digest = sha256(data)
    records = []
    for item in script.instructions:
        if item.opcode != 0x840 and item.offset not in allowed:
            continue
        text = decode_string(item.operands[0][1], encoding)
        record_id = sha256(f"{script_name}\0{digest}\0{item.offset}".encode("utf-8"))
        records.append({"id": record_id, "offset": item.offset, "kind": "text" if item.opcode == 0x840 else "ldstr",
                        "source": text, "translation": None})
    return {"schema": 1, "script": script_name, "source_sha256": digest, "encoding": encoding, "records": records}


def import_text(data, document, script_name, source_encoding, target_encoding, toolchain,
                ldstr_offsets=(), preserve_offsets=True):
    expected = export_text(data, script_name, source_encoding, ldstr_offsets)
    if not isinstance(document, dict) or set(document) != set(expected) or any(document[key] != expected[key] for key in expected if key != "records"):
        raise ValidationError("Text exchange source identity or schema mismatch")
    rows = document["records"]
    if not isinstance(rows, list) or len(rows) != len(expected["records"]):
        raise ValidationError("Missing or extra text records")
    changes = {}
    for given, original in zip(rows, expected["records"]):
        if not isinstance(given, dict) or set(given) != set(original) or any(given[key] != original[key] for key in original if key != "translation"):
            raise ValidationError("Unknown, duplicate, reordered or modified text record")
        text = given["translation"]
        if text is None or text == original["source"]:
            continue
        encode_string(text, target_encoding)
        if markers(text) != markers(original["source"]):
            raise ValidationError("Text exchange changed inline control-byte markers")
        changes[original["offset"]] = text
    if not changes:
        return data, {"structure_verified": True, "offsets_preserved": True, "old_saves": "unchanged_bytes", "changed_strings": 0}
    assembly = toolchain.disassemble(data, source_encoding)
    roundtrip = toolchain.assemble(assembly, source_encoding)
    verify_pair(data, roundtrip, source_encoding, source_encoding)
    script = Script(data)
    string_instructions = [item for item in script.instructions if ENCODINGS[item.opcode] == "s"]
    index, lines = 0, []
    pattern = re.compile(r'^(\s*(?:text|ldstr|ctrl)\s+)"(?:[^"\\]|\\.)*"(\s*(?:;.*)?)$')
    for line in assembly.splitlines():
        match = pattern.fullmatch(line)
        if match:
            if index >= len(string_instructions):
                raise ValidationError("Unexpected disassembled string instruction")
            item = string_instructions[index]
            index += 1
            if item.offset in changes:
                escaped = changes[item.offset].replace("\\", "\\\\").replace('"', '\\"')
                line = match[1] + '"' + escaped + '"' + match[2]
        lines.append(line)
    if index != len(string_instructions):
        raise ValidationError("Disassembly omitted string instructions")
    output = toolchain.assemble("\n".join(lines) + "\n", target_encoding)
    report = verify_pair(data, output, source_encoding, target_encoding, changes, preserve_offsets)
    verified_assembly = toolchain.disassemble(output, target_encoding)
    verify_pair(output, toolchain.assemble(verified_assembly, target_encoding), target_encoding, target_encoding)
    report["changed_strings"] = len(changes)
    return output, report
