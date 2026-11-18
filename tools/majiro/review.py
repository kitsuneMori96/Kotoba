"""Review documents built from the shipped script, so reviewers see exactly what ships."""
from .arc import ValidationError
from .mjo import export_text


def build_review(pristine, translated, script_name, source_encoding, target_encoding, ldstr_offsets, header, notes=()):
    """Pair pristine source strings with the translations read back from the output MJO.

    Reading the translated script back (instead of trusting a preview or commit
    file) is what keeps a review document from hiding a bad import: the reviewer
    and the game see the same bytes.
    """
    before = export_text(pristine, script_name, source_encoding, ldstr_offsets)
    after = export_text(translated, script_name, target_encoding, ldstr_offsets)
    if len(before["records"]) != len(after["records"]):
        raise ValidationError(f"Record count changed in output: {len(before['records'])} -> {len(after['records'])}")
    lines = [header, *notes, ""]
    for index, (source, result) in enumerate(zip(before["records"], after["records"])):
        if source["kind"] != result["kind"]:
            raise ValidationError(f"Record {index} changed kind in output: {source['kind']} -> {result['kind']}")
        translation = result["translation"]
        lines.append(f"[{index}] {source['kind']} @{source['offset']}")
        lines.append(f"日: {source['source']}")
        lines.append(f"中: {result['source']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def ldstr_offsets_of(document):
    return [record["offset"] for record in document.get("records", []) if record.get("kind") == "ldstr"]
