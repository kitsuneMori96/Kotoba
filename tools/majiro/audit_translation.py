"""Pre-deployment gate for translated MJO exchanges: coverage, line identity, ldstr inventory, ruby/choice integrity, format."""
import re

from .mjo import Script, decode_string, export_text, markers

KANA = re.compile(r"[ぁ-ヺㇰ-ㇿｦ-ﾝ]")
CJK = re.compile(r"[一-鿿々]")
DIGITS = re.compile(r"^[0-9０-９]+$")
PATHISH = re.compile(r"(\.txt$|\\)")
JUMP = re.compile(r"^\d{2}(プロローグ|おまけ|オマケ)")
RESOURCE = re.compile(r"[A-Za-z0-9_@.]")
RUBY_READ = re.compile(r"^[A-Za-zÀ-ɏḀ-ỿ\s]+$")
FORBIDDEN = ("*ldstr*", "*text*", "◇", "【", "】")
RUBY_HASH = bytes.fromhex("01fd9831")
PAIRS = {"「": "」", "『": "』", "（": "）"}


def _texts(script, encoding):
    return {item.offset: decode_string(item.operands[0][1], encoding)
            for item in script.instructions if item.opcode in (0x840, 0x801)}


def _groups(script, texts):
    ruby, choices = [], []
    run = []
    for item in script.instructions:
        if item.opcode == 0x801:
            run.append(item.offset)
            continue
        hashes = [value for kind, value in item.operands if kind == "h"]
        if len(run) >= 2 and RUBY_HASH in hashes:
            ruby.append(tuple(run[-2:]))
        elif len(run) >= 3 and DIGITS.match(texts[run[-2]]) and PATHISH.search(texts[run[-1]]) and hashes:
            choices.append(tuple(run[:-2]))
        run = []
    return ruby, choices


def audit_translation(data, document, script_name, encoding, nondisplay=None, terms=None, strict_terms=False,
                      kana_allowlist=None):
    nondisplay = {int(key): value for key, value in (nondisplay or {}).items()}
    kana_allowlist = {int(key): value for key, value in (kana_allowlist or {}).items()}
    script_name = script_name or document.get("script")
    script = Script(data)
    texts = _texts(script, encoding)
    flags = []

    def flag(check, offset, detail, severity="fail"):
        flags.append({"check": check, "offset": offset, "detail": detail, "severity": severity})

    allowed = sorted(r["offset"] for r in document["records"] if r["kind"] == "ldstr")
    expected = export_text(data, script_name, encoding, allowed)
    for key in ("schema", "script", "source_sha256", "encoding"):
        if document.get(key) != expected[key]:
            flag("identity", None, f"exchange {key} mismatch")
    if len(document["records"]) != len(expected["records"]):
        flag("identity", None, f"record count {len(document['records'])} != {len(expected['records'])}")
    else:
        for given, want in zip(document["records"], expected["records"]):
            for key in ("id", "offset", "kind", "source"):
                if given.get(key) != want[key]:
                    flag("identity", want["offset"], f"{key} mismatch")
    by_offset = {r["offset"]: r for r in document["records"]}

    for record in document["records"]:
        offset, dst = record["offset"], record["translation"]
        if dst is None:
            flag("coverage", offset, "untranslated record")
            continue
        if KANA.search(dst):
            if offset in kana_allowlist:
                kept = KANA.findall(dst)
                if not all(run in record["source"] for run in kept):
                    flag("kana-allowlist", offset,
                         f"allowlisted kana is not present in source: {dst!r} ({kana_allowlist[offset]})")
                elif record["kind"] == "text" and dst == record["source"]:
                    flag("coverage", offset, "allowlisted line is entirely untranslated")
            else:
                flag("format", offset, f"kana left in translation: {dst!r}")
        for token in FORBIDDEN:
            if token in dst:
                flag("format", offset, f"preview marker {token!r} in translation")
        if dst != dst.strip(" \t\r\n"):
            flag("format", offset, "ascii whitespace at translation edge", "warn")
        if markers(dst) != markers(record["source"]):
            flag("format", offset, "inline control-byte markers changed")
        if record["kind"] == "text" and dst == record["source"] and KANA.search(record["source"]):
            flag("coverage", offset, "translation identical to kana source")

    for offset, text in texts.items():
        if offset in by_offset or not (KANA.search(text) or CJK.search(text)):
            continue
        if offset in nondisplay or PATHISH.search(text) or JUMP.match(text):
            continue
        if not KANA.search(text) and RESOURCE.search(text):
            continue
        flag("ldstr-inventory", offset, f"user-visible candidate outside allowlist: {text!r}")
    for offset in allowed:
        text = texts[offset]
        if DIGITS.match(text) or PATHISH.search(text):
            flag("ldstr-inventory", offset, f"line number/debug path must not be allowlisted: {text!r}")

    ruby, choices = _groups(script, texts)
    for read, word in ruby:
        if read not in by_offset or word not in by_offset:
            flag("ruby", read, "ruby pair outside allowlist")
            continue
        rd, wd = by_offset[read]["translation"], by_offset[word]["translation"]
        if rd is None or (not RUBY_READ.match(rd) and read not in kana_allowlist):
            flag("ruby", read, f"ruby reading must be pinyin/latin: {rd!r}")
        if wd is None or not CJK.search(wd):
            flag("ruby", word, f"ruby word must be CJK: {wd!r}")
    for group in choices:
        for offset in group:
            record = by_offset.get(offset)
            if record is None:
                flag("choice", offset, "choice label outside allowlist")
            elif record["translation"] is None:
                flag("choice", offset, "choice label untranslated")

    stack = []
    for record in document["records"]:
        if record["kind"] != "text" or record["translation"] is None:
            continue
        for char in record["translation"]:
            if char in PAIRS:
                stack.append((char, record["offset"]))
            elif char in PAIRS.values():
                if not stack or PAIRS[stack[-1][0]] != char:
                    flag("brackets", record["offset"], f"unbalanced {char!r}")
                    stack = []
                else:
                    stack.pop()
    for char, offset in stack:
        flag("brackets", offset, f"unclosed {char!r}")

    if terms:
        from .terms import ledger_violations
        rows = [{"script": script_name, "offset": r["offset"], "kind": r["kind"],
                 "source": r["source"], "translation": r["translation"]}
                for r in document["records"]]
        for item in ledger_violations(rows, terms):
            severity = "fail" if (strict_terms and item["severity"] == "fail") else "warn"
            flag("term", item["offset"],
                 f"{item['term']} should read {item['expected']!r}, found {item['translation']!r}",
                 severity)

    fails = [f for f in flags if f["severity"] == "fail"]
    return {"script": script_name, "records": len(document["records"]),
            "text": sum(1 for r in document["records"] if r["kind"] == "text"),
            "ldstr": len(allowed), "ruby_pairs": len(ruby), "choice_groups": len(choices),
            "terms": sum(1 for f in flags if f["check"] == "term"),
            "kana_allowlist": len(kana_allowlist),
            "flags": flags, "fail": len(fails),
            "warn": len(flags) - len(fails), "pass": not fails}