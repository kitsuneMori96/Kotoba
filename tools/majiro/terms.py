"""Term ledger loading plus cross-chapter consistency checks.

The checks are mechanical on purpose: they compare existing translations with
each other and with the reviewed ledger, and never rewrite text.
"""
import json
from pathlib import Path

from .arc import ValidationError


def load_ledger(path):
    """Load agent_term_ledger.json ({"terms": {src: {...}}}) or a bare mapping."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    terms = document.get("terms") if isinstance(document, dict) and "terms" in document else document
    if not isinstance(terms, dict):
        raise ValidationError("Term ledger must be a mapping of source term to record")
    result = {}
    for source, record in terms.items():
        if not isinstance(source, str) or not isinstance(record, dict):
            raise ValidationError("Invalid term ledger entry")
        destination = record.get("dst")
        if not isinstance(destination, str) or not destination:
            continue
        result[source] = {"dst": destination,
                          "category": record.get("category") or "",
                          "note": record.get("note") or "",
                          "status": record.get("status") or "",
                          "occurrences": record.get("occurrences") or 0}
    return result


def _maximal_matches(text, terms):
    """Ledger terms occurring in text, dropping terms nested in a longer match."""
    hits = [term for term in terms if term and term in text]
    return [term for term in hits if not any(term != other and term in other for other in hits)]


def _base_name(text):
    """Strip Majiro's `＠` production/role marker: ルリ＠収録済み -> ルリ."""
    return text.split("＠")[0].strip()


def ledger_violations(rows, terms, minimum_length=2):
    """Records whose whole source is a reviewed term but whose translation drifts.

    Substring scanning was tried and rejected: terms like 境内 or おみくじ occur
    inside ordinary sentences where the reviewed rendering is not required.
    Whole-record (and ＠-stripped) matches are the cases where identity matters:
    nameplates, standalone labels, choice text.
    """
    violations = []
    for row in rows:
        source = (row["source"] or "").strip()
        destination = row.get("translation")
        if not source or not destination:
            continue
        base = _base_name(source)
        record = terms.get(base) or terms.get(source)
        if record is None or len(base) < minimum_length:
            continue
        if record["status"] == "deprecated" or record["dst"] in destination:
            continue
        violations.append({
            "script": row["script"], "offset": row["offset"], "kind": row["kind"],
            "term": base, "expected": record["dst"], "translation": destination,
            "category": record["category"],
            "severity": "fail" if record["status"] == "confirmed" else "warn",
        })
    return violations


def conflicts(rows, terms=None):
    """Same source string rendered with more than one translation."""
    table = {}
    for row in rows:
        source = (row["source"] or "").strip()
        destination = (row.get("translation") or "").strip()
        if not source or not destination:
            continue
        table.setdefault(source, {}).setdefault(destination, []).append(
            {"script": row["script"], "offset": row["offset"]})
    result = []
    for source, variants in table.items():
        if len(variants) < 2:
            continue
        ledger = (terms or {}).get(source)
        counts = {dst: len(places) for dst, places in variants.items()}
        result.append({
            "source": source,
            "variants": [{"translation": dst, "count": counts[dst], "places": variants[dst]}
                         for dst in sorted(variants, key=lambda d: -counts[d])],
            "recommended": ledger["dst"] if ledger else None,
            "category": ledger["category"] if ledger else "",
            "records": sum(counts.values()),
        })
    result.sort(key=lambda item: (-item["records"], item["source"]))
    return result


def reverse_conflicts(rows, terms=None, maximum_length=8):
    """A short Chinese term used for more than one Japanese source."""
    table = {}
    for row in rows:
        source = (row["source"] or "").strip()
        destination = (row.get("translation") or "").strip()
        if not source or not destination or len(destination) > maximum_length:
            continue
        table.setdefault(destination, {}).setdefault(source, []).append(
            {"script": row["script"], "offset": row["offset"]})
    result = []
    for destination, sources in table.items():
        if len(sources) < 2:
            continue
        result.append({
            "translation": destination,
            "sources": [{"source": src, "count": len(places), "places": places}
                        for src, places in sorted(sources.items(), key=lambda kv: -len(kv[1]))],
            "records": sum(len(places) for places in sources.values()),
        })
    result.sort(key=lambda item: (-item["records"], item["translation"]))
    return result


def check(rows, terms=None):
    violations = ledger_violations(rows, terms or {}) if terms else []
    same_source = conflicts(rows, terms)
    return {
        "schema": 1,
        "records": len(rows),
        "sources": len({row["source"] for row in rows if row["source"]}),
        "conflicts": same_source,
        "reverse": reverse_conflicts(rows, terms),
        "violations": violations,
        "summary": {
            "conflicts": len(same_source),
            "reverse": len(reverse_conflicts(rows, terms)),
            "violations": len(violations),
            "fails": sum(1 for item in violations if item["severity"] == "fail"),
        },
    }


def render_report(report):
    """Markdown table for human adjudication."""
    lines = ["# 译名一致性报告", "",
             f"扫描 {report['records']} 条已译记录、{report['sources']} 个唯一源文。",
             f"同源异译 {report['summary']['conflicts']} 处；"
             f"短词多源 {report['summary']['reverse']} 处；"
             f"台账冲突 {report['summary']['violations']} 条（其中 confirmed 级 {report['summary']['fails']} 条）。",
             "",
             "> 语气词、寒暄一类短句允许随语境微调，这里只作提醒；"
             "名牌、术语、选项请优先沿用「建议」列。", "",
             "## 一、同一句日文出现多种译法", "",
             "| 日文源 | 译法（次数） | 台账 | 建议 |", "| --- | --- | --- | --- |"]
    for item in report["conflicts"]:
        variants = " ／ ".join(f"{v['translation']}（{v['count']}）" for v in item["variants"])
        recommend = item["recommended"] or f"{item['variants'][0]['translation']}（沿用最多者）"
        lines.append(f"| {item['source']} | {variants} | {item['category'] or '—'} | {recommend} |")
    lines += ["", "## 二、同一中文短词对应多个日文源", "",
              "| 中文 | 日文源（次数） |", "| --- | --- |"]
    for item in report["reverse"]:
        sources = " ／ ".join(f"{s['source']}×{s['count']}" for s in item["sources"][:6])
        lines.append(f"| {item['translation']} | {sources} |")
    lines += ["", "## 三、与术语台账冲突的记录", "",
              "| 章 | 偏移 | 术语 | 应作 | 实际译文 | 级别 |", "| --- | --- | --- | --- | --- | --- |"]
    for item in report["violations"][:500]:
        translation = str(item["translation"]).replace("|", "\\|")
        lines.append(f"| {item['script']} | {item['offset']} | {item['term']} | {item['expected']} "
                     f"| {translation} | {item['severity']} |")
    if len(report["violations"]) > 500:
        lines.append(f"| … | 另有 {len(report['violations']) - 500} 条见 JSON | | | | |")
    return "\n".join(lines) + "\n"
