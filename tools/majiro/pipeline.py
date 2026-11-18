"""One-command chapter pipeline: audit gate, import, structure check, review document.

The pipeline never invents text and never deploys. It exists so the manual steps
that caused past incidents (missing --script-name, an existing report path, a
stale manifest) fail in one place with one message.
"""
import json
from pathlib import Path

from .arc import ValidationError, sha256
from .audit_translation import audit_translation
from .mjo import import_text, verify_pair
from .review import build_review, ldstr_offsets_of
from .toolchain import Toolchain


def file_key(name):
    """01ルリエロルート05 -> ero05; 01ルリ明るいルート05 -> route05; 00プロローグ05 -> prologue05."""
    if "エロルート" in name:
        return "ero" + name[-2:]
    if "明るいルート" in name:
        return "route" + name[-2:]
    if "プロローグ" in name:
        return "prologue" + name[-2:]
    return name


def review_label(name):
    if "明るいルート" in name:
        return "明亮路线" + name[-2:]
    if "プロローグ" in name:
        return "共通线序幕" + name[-2:]
    return file_key(name)


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, document):
    path = Path(path)
    if path.exists():
        raise ValidationError(f"Report path must not exist: {path}")
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def paths(name, workdir):
    workdir = Path(workdir)
    key = file_key(name)
    exchange = None
    for candidate in (workdir / f"{key}.pristine.exchange.json", workdir / f"{key}.exchange.json"):
        if candidate.exists():
            exchange = candidate
            break
    return {
        "key": key,
        "pristine": workdir / "src" / f"{name}.pristine.mjo",
        "exchange": exchange,
        "nondisplay": workdir / "agent" / f"nondisplay-{key}.json",
        "output": workdir / f"{name}.zh.mjo",
        "audit": workdir / "agent" / f"{key}.audit.json",
        "import_report": workdir / "agent" / f"import-{key}-report.json",
        "review": workdir / f"审校-{review_label(name)}-全文.txt",
    }


def run_chapter(name, workdir, tool, source_encoding="cp932", target_encoding="utf8",
                review_title=None, dry_run=False):
    where = paths(name, workdir)
    if not where["pristine"].exists():
        raise ValidationError(f"Missing pristine source: {where['pristine']}")
    if where["exchange"] is None:
        raise ValidationError(f"Missing exchange for {name} (looked for {where['key']}.pristine.exchange.json)")
    document = load_json(where["exchange"])
    offsets = ldstr_offsets_of(document)
    pristine = where["pristine"].read_bytes()

    gate = audit_translation(pristine, document, name, source_encoding,
                             load_json(where["nondisplay"]) if where["nondisplay"].exists() else None)
    if dry_run:
        return {"script": name, "dry_run": True, "audit": {"fail": gate["fail"], "warn": gate["warn"]},
                "exchange": str(where["exchange"])}
    if not gate["pass"]:
        raise ValidationError(f"Audit gate failed for {name}: {gate['fail']} blocking flag(s)")
    for key in ("output", "audit", "import_report", "review"):
        if where[key].exists():
            raise ValidationError(f"Output must be new: {where[key]}")
    write_json(where["audit"], gate)

    output, imported = import_text(pristine, document, name, source_encoding, target_encoding,
                                   Toolchain(tool), offsets, False)
    where["output"].write_bytes(output)
    write_json(where["import_report"], imported)
    replacements = {record["offset"]: record["translation"] for record in document["records"]
                    if record.get("translation") not in (None, record["source"])}
    structure = verify_pair(pristine, output, source_encoding, target_encoding,
                            replacements, preserve_offsets=False)

    header = (f"{review_title or name} 全文审校稿\n"
              f"{gate['records']} 条 = {gate['text']} text + {gate['ldstr']} ldstr；"
              f"审计门 pass，导入 changed={imported.get('changed_strings')}，终稿 {len(output)}B。")
    where["review"].write_text(
        build_review(pristine, output, name, source_encoding, target_encoding, offsets, header),
        encoding="utf-8")
    return {"script": name, "audit": {"fail": gate["fail"], "warn": gate["warn"]},
            "import": imported, "structure": structure, "bytes": len(output),
            "sha256": sha256(output), "output": str(where["output"]), "review": str(where["review"])}
