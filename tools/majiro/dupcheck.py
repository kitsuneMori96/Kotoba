"""Compare a freshly exported chapter against already-translated ones.

Identical source sequences mean the same script shipped under a second
encryption (the death-route prologue is the bright-route prologue verbatim), so
the chapter needs no new translation at all; partial overlap only means the
reused lines still have to be checked for context.
"""
import json
from pathlib import Path

from .arc import ValidationError


def _filled(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    records = document.get("records", [])
    if not records or any(r.get("translation") in (None, "") for r in records):
        return None
    return document


def duplicate_report(target, directory):
    path = Path(target)
    pending = json.loads(path.read_text(encoding="utf-8"))
    keys = [(r["kind"], r["source"]) for r in pending["records"]]
    pool = {}
    for other in sorted(Path(directory).glob("*.pristine.exchange.json")):
        if other.resolve() == path.resolve():
            continue
        document = _filled(other)
        if document is None:
            continue
        for record in document["records"]:
            pool.setdefault((record["kind"], record["source"]), (other.name, record["translation"]))
    hits = [pool[key] for key in keys if key in pool]
    same_sequence = False
    for other in sorted(Path(directory).glob("*.pristine.exchange.json")):
        if other.resolve() == path.resolve():
            continue
        document = _filled(other)
        if document is not None and [(r["kind"], r["source"]) for r in document["records"]] == list(keys):
            same_sequence = other.name
            break
    return {
        "script": pending.get("script", path.name),
        "records": len(keys),
        "reused": len(hits),
        "untranslated": len(keys) - len(hits),
        "identical_to": same_sequence,
        "verdict": ("duplicate script copy: reuse every translation, translate nothing"
                    if same_sequence and len(hits) == len(keys)
                    else "partial overlap: reuse hits but review each for context" if hits
                    else "no overlap: translate from scratch"),
    }


def run(target, directory, out=None):
    report = duplicate_report(target, directory)
    if out:
        destination = Path(out)
        if destination.exists():
            raise ValidationError(f"Report output must be new: {destination}")
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return report


def apply_reuse(target, directory, batch=160):
    """Fill every record whose exact source is already translated, as commit files.

    Only byte-identical sources are reused; overlapping lines whose wording may
    carry a different meaning in the new route stay untranslated for a human
    pass. Commit files land in <directory>/agent/commits so the audit gate can
    still see what happened.
    """
    path = Path(target)
    document = json.loads(path.read_text(encoding="utf-8"))
    script = document.get("script", path.stem)
    pool = {}
    for other in sorted(Path(directory).glob("*.pristine.exchange.json")):
        if other.resolve() == path.resolve():
            continue
        filled = _filled(other)
        if filled is None:
            continue
        for record in filled["records"]:
            pool[(record["kind"], record["source"])] = record["translation"]
    records = document["records"]
    matched = [i for i, r in enumerate(records)
               if r.get("translation") in (None, "") and (r["kind"], r["source"]) in pool]
    if not matched:
        return {"reusable": 0, "remaining": sum(1 for r in records if r.get("translation") in (None, "")),
                "commits": []}
    commit_dir = Path(directory) / "agent" / "commits"
    commit_dir.mkdir(parents=True, exist_ok=True)
    runs, run = [], [matched[0]]
    for index in matched[1:]:                      # apply_commit demands contiguous id batches
        if index == run[-1] + 1 and len(run) < batch:
            run.append(index)
        else:
            runs.append(run)
            run = [index]
    runs.append(run)
    written = []
    for number, ids in enumerate(runs):
        name = f"{script}-reuse-{number:03d}.json"
        destination = commit_dir / name
        if destination.exists():
            raise ValidationError(f"Commit file must be new: {destination}")
        payload = {"translations": [{"id": i, "dst": pool[(records[i]["kind"], records[i]["source"])]}
                                    for i in ids],
                   "term_updates": [], "agent_suggest": [], "file_note_patch": {}}
        destination.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        written.append(str(destination))
    return {"reusable": len(matched), "remaining": len(records) - len(matched), "commits": written}

