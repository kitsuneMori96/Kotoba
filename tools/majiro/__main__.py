import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .arc import Archive, ValidationError, file_sha256, name_key, sha256
from .audit import audit, load_json, new_json
from .mjo import Script, export_text, import_text, verify_pair
from .toolchain import ToolchainError


def new_bytes(path, data):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".ruri-output-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def parser():
    root = argparse.ArgumentParser(description="Local Majiro validation and patch tools; private game data must stay local.")
    commands = root.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("audit", help="Read-only source inventory; unresolved changes return exit code 2")
    cmd.add_argument("--original", type=Path, required=True)
    cmd.add_argument("--target", type=Path, required=True)
    cmd.add_argument("--exe", required=True)
    cmd.add_argument("--allowlist", type=Path)
    cmd.add_argument("--out", type=Path, required=True, help="New local JSON report path")
    cmd = commands.add_parser("verify-arc", help="Validate a Majiro ARC V3 without extracting it")
    cmd.add_argument("archive", type=Path)
    cmd = commands.add_parser("rebuild-arc", help="Replace explicitly listed entries, checking source digests")
    cmd.add_argument("archive", type=Path)
    cmd.add_argument("--manifest", type=Path, required=True)
    cmd.add_argument("--out", type=Path, required=True)
    for name in ("export", "import"):
        cmd = commands.add_parser(name, help=f"{name.capitalize()} reviewed text records; no automatic translation")
        cmd.add_argument("script", type=Path)
        cmd.add_argument("--encoding", choices=("cp932", "utf8"), required=True)
        cmd.add_argument("--script-name", help="Stable logical script name; defaults to the input filename")
        cmd.add_argument("--ldstr-offset", type=lambda value: int(value, 0), action="append", default=[], help="Explicitly reviewed ldstr bytecode offset, repeatable")
        cmd.add_argument("--out", type=Path, required=True)
        if name == "import":
            cmd.add_argument("--exchange", type=Path, required=True)
            cmd.add_argument("--tool", type=Path, required=True, help="Pinned MajiroTools maji.dll or maji.exe")
            cmd.add_argument("--target-encoding", choices=("cp932", "utf8"), required=True)
            cmd.add_argument("--allow-offset-changes", action="store_true", help="Opt out of static old-save offset protection; never implies runtime compatibility")
            cmd.add_argument("--report", type=Path, required=True)
    cmd = commands.add_parser("audit-translation", help="Pre-deployment gate: coverage, line identity, ldstr inventory, ruby/choice integrity, format")
    cmd.add_argument("script", type=Path)
    cmd.add_argument("--encoding", choices=("cp932", "utf8"), required=True)
    cmd.add_argument("--script-name", help="Stable logical script name; defaults to the exchange script name")
    cmd.add_argument("--exchange", type=Path, required=True)
    cmd.add_argument("--nondisplay", type=Path, help="JSON {ldstr offset: reason} for reviewed non-display strings")
    cmd.add_argument("--term-ledger", type=Path, help="agent_term_ledger.json; flags records that break a reviewed term")
    cmd.add_argument("--term-strict", action="store_true", help="Treat confirmed-term deviations as blocking, not warnings")
    cmd.add_argument("--out", type=Path, required=True, help="New local JSON report path")
    cmd = commands.add_parser("term-check", help="Cross-chapter term consistency: same source, different translation")
    cmd.add_argument("--exchange-dir", type=Path, required=True)
    cmd.add_argument("--ledger", type=Path, required=True)
    cmd.add_argument("--out", type=Path, required=True, help="New local JSON report path")
    cmd.add_argument("--md", type=Path, help="Optional new Markdown adjudication table")
    cmd = commands.add_parser("dupcheck", help="Report how much of a fresh exchange is already translated elsewhere")
    cmd.add_argument("exchange", type=Path)
    cmd.add_argument("--directory", type=Path, required=True)
    cmd.add_argument("--out", type=Path, help="New local JSON report path")
    cmd.add_argument("--apply-reuse", action="store_true",
                     help="Write contiguous reuse commit files instead of only reporting")
    cmd = commands.add_parser("corpus", help="Regenerate the corpus TSV, term table, index and conflict report")
    cmd.add_argument("--directory", type=Path, required=True)
    cmd.add_argument("--ledger", type=Path)
    cmd = commands.add_parser("review", help="Rebuild a review document from the shipped MJO, not from a preview")
    cmd.add_argument("--pristine", type=Path, required=True)
    cmd.add_argument("--translated", type=Path, required=True)
    cmd.add_argument("--exchange", type=Path, required=True)
    cmd.add_argument("--script-name", required=True)
    cmd.add_argument("--encoding", choices=("cp932", "utf8"), default="cp932")
    cmd.add_argument("--target-encoding", choices=("cp932", "utf8"), default="utf8")
    cmd.add_argument("--title")
    cmd.add_argument("--out", type=Path, required=True)
    cmd = commands.add_parser("chapter", help="Run audit -> import -> structure check -> review document for one chapter")
    cmd.add_argument("--name", required=True, help="Logical script name, e.g. 01ルリエロルート05")
    cmd.add_argument("--workdir", type=Path, required=True)
    cmd.add_argument("--tool", type=Path, required=True)
    cmd.add_argument("--encoding", choices=("cp932", "utf8"), default="cp932")
    cmd.add_argument("--target-encoding", choices=("cp932", "utf8"), default="utf8")
    cmd.add_argument("--review-title")
    cmd.add_argument("--dry-run", action="store_true", help="Run only the audit gate")
    cmd = commands.add_parser("deploy-chapter", help="Rebuild a test ARC with one chapter: manifest, diff, backup, optional restart")
    cmd.add_argument("--arc", type=Path, required=True)
    cmd.add_argument("--entry", required=True, help="ARC entry name, e.g. 01ルリエロルート05.mjo")
    cmd.add_argument("--zh", type=Path, required=True)
    cmd.add_argument("--manifest", type=Path, required=True)
    cmd.add_argument("--backup", type=Path, required=True)
    cmd.add_argument("--expect-entries", type=int)
    cmd.add_argument("--exe", type=Path, help="Absolute game executable for an optional restart")
    cmd.add_argument("--restart", action="store_true")
    cmd.add_argument("--dry-run", action="store_true")
    cmd = commands.add_parser("verify-mjo", help="Check bytecode structure or compare a no-content-change round trip")
    cmd.add_argument("script", type=Path)
    cmd.add_argument("--against", type=Path)
    cmd.add_argument("--encoding", choices=("cp932", "utf8"), default="cp932")
    cmd.add_argument("--target-encoding", choices=("cp932", "utf8"))
    cmd.add_argument("--allow-offset-changes", action="store_true")
    cmd = commands.add_parser("build-toolchain", help="Build pinned MajiroTools from a local source checkout")
    cmd.add_argument("source", type=Path)
    cmd.add_argument("--out", type=Path, required=True)
    for name in ("build", "verify", "install"):
        cmd = commands.add_parser(name, help={"build": "Build a private directory package without changing the target", "verify": "Dry-run package installation and verify input digests", "install": "Install a verified package with persistent recovery state"}[name])
        cmd.add_argument("--target", type=Path, required=True)
        if name == "build":
            cmd.epilog = ('Spec example: {"schema":1,"executable":{"path":"game.exe","sha256":"<host SHA-256>"},'
                          '"files":[{"path":"winmm.dll","source":"new-winmm.dll",'
                          '"before_sha256":"<installed SHA-256, or null if absent>","reason":"reviewed change"}]}. '
                          'Source paths are relative to the spec. Script updates also require "audit":"audit.json". '
                          'Packages are local and unsigned; hashes check integrity, not publisher identity. '
                          'No runtime or old-save compatibility is implied.')
            cmd.add_argument("--spec", type=Path, required=True)
            cmd.add_argument("--out", type=Path, required=True)
        else:
            cmd.add_argument("package", type=Path)
        if name == "install":
            cmd.add_argument("--dry-run", action="store_true", help="Show exact replacements without creating state or changing files")
    for name in ("rollback", "recover"):
        cmd = commands.add_parser(name, help="Restore pre-install files only if current digests match this transaction")
        cmd.add_argument("--target", type=Path, required=True)
    return root


def run(args):
    if args.command == "audit":
        result = audit(args.original, args.target, args.exe, args.allowlist)
        new_json(args.out, result)
        print(json.dumps(result["counts"]))
        return 0 if result["safe_to_build"] else 2
    if args.command == "verify-arc":
        archive = Archive(args.archive)
        print(json.dumps({"valid": True, "entries": len(archive.entries)}))
    elif args.command == "rebuild-arc":
        document = load_json(args.manifest)
        if not isinstance(document, dict) or set(document) != {"archive_sha256", "replacements"} or document["archive_sha256"] != file_sha256(args.archive):
            raise ValidationError("ARC replacement manifest or input digest mismatch")
        archive = Archive(args.archive)
        replacements, seen = {}, set()
        if not isinstance(document["replacements"], list):
            raise ValidationError("Replacements must be an array")
        for row in document["replacements"]:
            if not isinstance(row, dict) or set(row) != {"name", "file", "before_sha256"}:
                raise ValidationError("Invalid ARC replacement record")
            key = name_key(row["name"])
            if key in seen or key not in archive.by_name or sha256(archive.read(row["name"])) != row["before_sha256"]:
                raise ValidationError("Unknown, duplicate or stale ARC replacement")
            seen.add(key)
            replacements[row["name"]] = (args.manifest.parent / row["file"]).read_bytes()
        archive.rebuild(replacements, args.out)
        print(json.dumps({"verified": True, "replaced_entries": len(replacements)}))
    elif args.command in ("export", "import"):
        data = args.script.read_bytes()
        name = args.script_name or args.script.name
        if args.command == "export":
            result = export_text(data, name, args.encoding, args.ldstr_offset)
            new_json(args.out, result)
            print(json.dumps({"records": len(result["records"])}))
        else:
            from .toolchain import Toolchain
            if args.out.exists() or args.report.exists() or args.out.resolve() == args.report.resolve():
                raise ValidationError("Output and report must be distinct new files")
            tool = Toolchain(args.tool)
            tool.verify()
            output, report = import_text(data, load_json(args.exchange), name, args.encoding, args.target_encoding,
                                         tool, args.ldstr_offset, not args.allow_offset_changes)
            new_bytes(args.out, output)
            new_json(args.report, report)
            print(json.dumps(report))
    elif args.command == "audit-translation":
        from .audit_translation import audit_translation
        terms = None
        if args.term_ledger:
            from .terms import load_ledger
            terms = load_ledger(args.term_ledger)
        result = audit_translation(args.script.read_bytes(), load_json(args.exchange),
                                   args.script_name, args.encoding,
                                   load_json(args.nondisplay) if args.nondisplay else None,
                                   terms, args.term_strict)
        new_json(args.out, result)
        print(json.dumps({key: result[key] for key in ("records", "ldstr", "ruby_pairs", "choice_groups", "terms", "fail", "warn", "pass")}))
        return 0 if result["pass"] else 2
    elif args.command == "term-check":
        from .corpus import rows_from, exchange_files, write_tsv
        from .terms import check, load_ledger, render_report
        rows, _ = rows_from(exchange_files(args.exchange_dir))
        report = check(rows, load_ledger(args.ledger))
        new_json(args.out, report)
        if args.md:
            args.md.write_text(render_report(report), encoding="utf-8")
        print(json.dumps(report["summary"]))
        return 0 if not report["summary"]["fails"] else 3
    elif args.command == "dupcheck":
        from .dupcheck import apply_reuse, run
        report = apply_reuse(args.exchange, args.directory) if args.apply_reuse else run(args.exchange, args.directory, args.out)
        print(json.dumps(report, ensure_ascii=False))
    elif args.command == "corpus":
        from .corpus import write_all
        result = write_all(args.directory, args.ledger)
        print(json.dumps(result["report"]["summary"] | {"chapters": len(result["stats"]),
                                                        "records": len(result["rows"])}))
        return 0 if not result["report"]["summary"]["fails"] else 3
    elif args.command == "review":
        from .review import build_review, ldstr_offsets_of
        document = load_json(args.exchange)
        text = build_review(args.pristine.read_bytes(), args.translated.read_bytes(),
                            args.script_name, args.encoding, args.target_encoding,
                            ldstr_offsets_of(document),
                            args.title or f"{args.script_name} 全文审校稿")
        if args.out.exists():
            raise ValidationError("Review output must not exist")
        args.out.write_text(text, encoding="utf-8")
        print(json.dumps({"records": len(document["records"]), "out": str(args.out)}))
    elif args.command == "chapter":
        from .pipeline import run_chapter
        print(json.dumps(run_chapter(args.name, args.workdir, args.tool, args.encoding,
                                     args.target_encoding, args.review_title, args.dry_run),
                         ensure_ascii=False))
    elif args.command == "deploy-chapter":
        from .deploy import deploy_chapter, restart_game
        result = deploy_chapter(args.arc, args.entry, args.zh, args.manifest, args.backup,
                                args.expect_entries, args.dry_run)
        if args.restart and not args.dry_run:
            if not args.exe:
                raise ValidationError("--restart requires --exe")
            result["game"] = restart_game(args.exe)
        print(json.dumps(result, ensure_ascii=False))
    elif args.command == "verify-mjo":
        data = args.script.read_bytes()
        if args.against:
            result = verify_pair(data, args.against.read_bytes(), args.encoding,
                                 args.target_encoding or args.encoding, preserve_offsets=not args.allow_offset_changes)
        else:
            script = Script(data)
            result = {"valid": True, "instructions": len(script.instructions), "functions": len(script.functions)}
        print(json.dumps(result))
    elif args.command == "build-toolchain":
        from .toolchain import build_toolchain
        result = build_toolchain(args.source, args.out)
        print(json.dumps({"tool": str(result)}))
    else:
        from . import package
        if args.command == "build":
            result = package.build(args.spec, args.target, args.out)
        elif args.command in ("verify", "install"):
            operation = "verify" if args.command == "install" and args.dry_run else args.command
            result = getattr(package, operation)(args.package, args.target)
        else:
            result = getattr(package, args.command)(args.target)
        print(json.dumps(result, ensure_ascii=True))
    return 0


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (ToolchainError, ValidationError, OSError, UnicodeError, KeyError, TypeError, ValueError) as exc:
        print("ERROR: " + str(exc).encode("ascii", "backslashreplace").decode("ascii"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
