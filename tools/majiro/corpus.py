"""Build the cross-chapter corpus indexes used for terminology and style review."""
import json
from pathlib import Path

from .arc import ValidationError
from .terms import check, render_report


def exchange_files(directory):
    """Every exchange JSON in directory, one per script, preferring pristine exports."""
    directory = Path(directory)
    chosen = {}
    for path in sorted(directory.glob("*.exchange.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        script = document.get("script") if isinstance(document, dict) else None
        if not isinstance(script, str):
            continue
        script = script[:-4] if script.endswith(".mjo") else script
        script = script[:-9] if script.endswith(".pristine") else script
        filled = sum(1 for row in document.get("records") or [] if row.get("translation"))
        rank = (filled, "pristine" in path.name)
        if script not in chosen or rank > chosen[script][0]:
            chosen[script] = (rank, path, document)
    return [{"script": script, "path": item[1], "document": item[2]}
            for script, item in sorted(chosen.items())]


def rows_from(files):
    rows, stats = [], []
    for entry in files:
        document = entry["document"]
        records = document["records"]
        filled = 0
        for record in records:
            translation = (record.get("translation") or "").strip()
            if translation:
                filled += 1
            rows.append({"script": entry["script"], "kind": record.get("kind", ""),
                         "id": record.get("id", ""), "offset": record.get("offset", ""),
                         "source": (record.get("source") or "").strip(),
                         "translation": translation})
        stats.append({"script": entry["script"], "records": len(records), "filled": filled})
    return rows, stats


def _clean(value):
    return str(value).replace("\t", " ").replace("\n", "\\n")


def write_tsv(rows, path):
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("章\tkind\tid\toffset\t日文源\t中文译\n")
        for row in rows:
            stream.write("\t".join(_clean(row[key]) for key in
                                   ("script", "kind", "id", "offset", "source", "translation")) + "\n")


def write_term_table(terms, path):
    buckets = {}
    for source, record in terms.items():
        buckets.setdefault(record["category"] or "未分类", []).append((source, record))
    lines = ["# 琉璃交错 · 术语总表", "",
             f"共 {len(terms)} 条，源自 `agent/agent_term_ledger.json`。由 `python -m tools.majiro corpus` 生成，勿手改。",
             "", "翻译新章优先查此表；同义异译以本表为准。", ""]
    for category in sorted(buckets, key=lambda name: (-len(buckets[name]), name)):
        items = sorted(buckets[category], key=lambda item: (-item[1]["occurrences"], item[0]))
        lines += [f"## {category}（{len(items)}）", "",
                  "| 日文 | 中文 | 次数 | 状态 | 备注 |", "| --- | --- | --- | --- | --- |"]
        for source, record in items:
            note = record["note"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {source} | {record['dst']} | {record['occurrences']} "
                         f"| {record['status']} | {note} |")
        lines.append("")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_index(stats, directory, path):
    directory = Path(directory)
    lines = ["# 已译语料索引", "",
             f"总记录 {sum(item['records'] for item in stats)} 条，已译 "
             f"{sum(item['filled'] for item in stats)} 条。",
             "机器可读全量对照见 `语料-已译全量.tsv`（UTF-8、Tab 分隔，可直接 grep）。", "",
             "| 章 | 记录数 | 已译 | 审校稿 |", "| --- | --- | --- | --- |"]
    for item in stats:
        script, suffix = item["script"], item["script"][-2:]
        if script.startswith("00プロローグ"):
            review = f"审校-共通线序幕{suffix}-全文.txt"
        elif script.startswith("01ルリ明るいルート"):
            review = f"审校-明亮路线{suffix}-全文.txt"
        elif script.startswith("01ルリエロルート"):
            review = f"审校-ero{suffix}-全文.txt"
        else:
            review = ""
        lines.append(f"| {script} | {item['records']} | {item['filled']} | "
                     f"{review if review and (directory / review).exists() else '—'} |")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def build(directory, ledger_path=None):
    files = exchange_files(directory)
    if not files:
        raise ValidationError("No exchange files found")
    rows, stats = rows_from(files)
    terms = None
    if ledger_path:
        from .terms import load_ledger
        terms = load_ledger(ledger_path)
    report = check(rows, terms)
    return {"directory": Path(directory), "rows": rows, "stats": stats,
            "terms": terms or {}, "report": report}


def write_all(directory, ledger_path=None):
    result = build(directory, ledger_path)
    directory = result["directory"]
    write_tsv(result["rows"], directory / "语料-已译全量.tsv")
    write_index(result["stats"], directory, directory / "语料索引.md")
    if result["terms"]:
        write_term_table(result["terms"], directory / "术语总表.md")
    (directory / "译名一致性报告.md").write_text(render_report(result["report"]), encoding="utf-8")
    return result
