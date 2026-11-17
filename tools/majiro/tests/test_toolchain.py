"""Synthetic-only tests; optional local integration paths are supplied explicitly."""

import copy
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools.majiro import toolchain as tc


MJIL = ('readmark disable\nfunc $12345678() entrypoint {\nentry:\n'
        ' argcheck []\n alloca []\n text "synthetic"\n proc\n ldc.i 0\n ret\n}\n')


def mjo(magic=tc.MAGIC):
    code = b"\x36\x08\x00\x00\x29\x08\x00\x00\x00\x08\x00\x00\x00\x00\x2b\x08"
    return magic + struct.pack("<IIIII", 0, 0, 1, 0x12345678, 0) + struct.pack("<I", len(code)) + code


def tar_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


class TemporaryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kotoba-maji-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def patch(self, name, **kwargs):
        patcher = patch.object(tc, name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()


class InvocationTests(TemporaryTest):
    def setUp(self):
        super().setUp()
        self.dll = self.root / "maji.dll"
        self.dll.write_bytes(b"synthetic executable placeholder")
        self.tool = tc.Toolchain(self.dll)
        self.dotnet = self.patch("_dotnet", return_value=str(self.root / "dotnet.exe"))
        self.calls = []
        self.result_data = None
        self.stdout = b""
        self.stderr = b""
        self.returncode = 0
        self.write_output = True
        self.process = patch.object(tc.subprocess, "run", side_effect=self.run_tool)
        self.addCleanup(self.process.stop)
        self.runner = self.process.start()

    def run_tool(self, args, **kwargs):
        operation = "assemble" if "assemble" in args else "disassemble"
        source = Path(args[args.index(operation) + 1])
        self.calls.append((args, kwargs, source.read_bytes()))
        self.assertEqual(source.parent, Path(kwargs["cwd"]))
        self.assertNotEqual(source.parent, self.root)
        self.assertTrue(source.is_absolute())
        self.assertEqual(kwargs["timeout"], 180)
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["env"]["DOTNET_ROLL_FORWARD"], "LatestMajor")
        self.assertNotIn("--cfg=false", args)
        target = source.with_suffix(".mjo" if operation == "assemble" else ".mjil")
        self.assertFalse(target.exists())
        if self.write_output:
            data = self.result_data
            if data is None:
                data = mjo() if operation == "assemble" else MJIL.encode("utf-8")
            target.write_bytes(data)
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, self.stderr)

    def test_assemble_arguments_and_cp932_environment(self):
        with patch.dict(os.environ, {"MAJIRO_STRENC": "utf8"}):
            self.assertEqual(self.tool.assemble(MJIL, "cp932"), mjo())
            self.assertEqual(os.environ["MAJIRO_STRENC"], "utf8")
        args, kwargs, content = self.calls[-1]
        self.assertEqual(args[:3], [str(self.root / "dotnet.exe"), str(self.dll), "assemble"])
        self.assertEqual(args[4:], ["--externalized=false", "--encrypt=false", "-q"])
        self.assertFalse(any(key.upper() == "MAJIRO_STRENC" for key in kwargs["env"]))
        self.assertEqual(content, MJIL.encode("utf-8"))
        self.assertFalse(Path(kwargs["cwd"]).exists())
        self.assertEqual(list(self.root.iterdir()), [self.dll])

    def test_disassemble_arguments_utf8_and_bom(self):
        self.result_data = b"\xef\xbb\xbf" + MJIL.encode("utf-8")
        self.assertEqual(self.tool.disassemble(mjo(), "utf8"), MJIL)
        args, kwargs, content = self.calls[-1]
        self.assertEqual(args[2], "disassemble")
        self.assertEqual(args[4:], ["-e=false", "-q"])
        self.assertEqual(kwargs["env"]["MAJIRO_STRENC"], "utf8")
        self.assertEqual(content, mjo())

    def test_all_calls_use_independent_temporary_directories(self):
        stale = self.root / "input.mjo"
        stale.write_bytes(mjo())
        self.tool.assemble(MJIL, "cp932")
        self.tool.disassemble(mjo(), "cp932")
        directories = [kwargs["cwd"] for _, kwargs, _ in self.calls]
        self.assertEqual(len(set(directories)), 2)
        self.assertTrue(all(not Path(directory).exists() for directory in directories))
        self.assertEqual(stale.read_bytes(), mjo())

    def test_exit_zero_error_diagnostics_are_fatal_even_with_valid_output(self):
        diagnostics = [b"Error: bad syntax", b"System.FormatException: bad input",
                       b"Failed to disassemble script", b"Command assemble failed with an error:",
                       b"\x1b[31mERROR\x1b[0m: broken", b"Unable to parse", b"Invalid opcode",
                       b"Fatal failure", b"Could not load assembly", b"Unsupported instruction"]
        for operation in ("assemble", "disassemble"):
            for diagnostic in diagnostics:
                for stream in ("stdout", "stderr"):
                    with self.subTest(operation=operation, diagnostic=diagnostic, stream=stream):
                        self.stdout = self.stderr = b""
                        setattr(self, stream, diagnostic)
                        with self.assertRaises(tc.ToolchainError):
                            getattr(self.tool, operation)(MJIL if operation == "assemble" else mjo(), "cp932")
                        self.assertFalse(Path(self.calls[-1][1]["cwd"]).exists())

    def test_nonzero_exit_is_fatal(self):
        self.returncode = 7
        with self.assertRaisesRegex(tc.ToolchainError, "exit 7"):
            self.tool.assemble(MJIL, "cp932")

    def test_missing_output_is_fatal_and_stale_sibling_is_not_used(self):
        (self.root / "input.mjo").write_bytes(mjo())
        self.write_output = False
        for method, content in ((self.tool.assemble, MJIL), (self.tool.disassemble, mjo())):
            with self.subTest(method=method.__name__), self.assertRaisesRegex(tc.ToolchainError, "Missing file"):
                method(content, "cp932")

    def test_empty_output_is_fatal(self):
        self.result_data = b""
        for method, content in ((self.tool.assemble, MJIL), (self.tool.disassemble, mjo())):
            with self.subTest(method=method.__name__), self.assertRaisesRegex(tc.ToolchainError, "empty"):
                method(content, "utf8")

    def test_blank_or_non_utf8_disassembly_is_fatal(self):
        for data in (b" \r\n", b"\xef\xbb\xbf", b"\xff"):
            with self.subTest(data=data), self.assertRaises(tc.ToolchainError):
                self.result_data = data
                self.tool.disassemble(mjo(), "cp932")

    def test_invalid_assembled_mjo_is_fatal(self):
        variants = [b"junk", b"X" * len(mjo()), mjo()[:-1], mjo() + b"extra", mjo(tc.ENCRYPTED_MAGIC)]
        large_count = bytearray(mjo())
        struct.pack_into("<I", large_count, 24, 0xFFFFFFFF)
        variants.append(bytes(large_count))
        bad_entry = bytearray(mjo())
        struct.pack_into("<I", bad_entry, 16, 0xFFFFFFFF)
        variants.append(bytes(bad_entry))
        for data in variants:
            with self.subTest(data=data), self.assertRaises(tc.ToolchainError):
                self.result_data = data
                self.tool.assemble(MJIL, "cp932")

    def test_invalid_input_never_invokes_tool(self):
        for data in (b"", b"bad", mjo()[:-1], mjo() + b"extra"):
            with self.subTest(data=data), self.assertRaises(tc.ToolchainError):
                self.tool.disassemble(data, "cp932")
        self.runner.assert_not_called()

    def test_encrypted_magic_is_allowed_for_disassembly_only(self):
        self.assertEqual(self.tool.disassemble(mjo(tc.ENCRYPTED_MAGIC), "cp932"), MJIL)

    def test_only_exact_encoding_names_are_accepted(self):
        for encoding in (None, "", "shift_jis", "CP932", "utf-8", "UTF8"):
            for method, content in ((self.tool.assemble, MJIL), (self.tool.disassemble, mjo())):
                with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                    method(content, encoding)
        self.runner.assert_not_called()

    def test_timeout_cleans_up_and_is_not_retried(self):
        def timeout(args, **kwargs):
            self.calls.append((args, kwargs, None))
            raise subprocess.TimeoutExpired(args, 180, output=b"partial", stderr=b"stalled")
        self.runner.side_effect = timeout
        with self.assertRaisesRegex(tc.ToolchainError, "timed out after 180s"):
            self.tool.assemble(MJIL, "utf8")
        self.runner.assert_called_once()
        self.assertFalse(Path(self.calls[0][1]["cwd"]).exists())

    def test_oserror_is_reported(self):
        self.runner.side_effect = FileNotFoundError("no local runtime")
        with self.assertRaisesRegex(tc.ToolchainError, "Cannot run local command"):
            self.tool.assemble(MJIL, "cp932")

    def test_exe_runs_directly_without_dotnet(self):
        exe = self.root / "maji.exe"
        exe.write_bytes(b"synthetic executable placeholder")
        tc.Toolchain(exe).assemble(MJIL, "cp932")
        self.assertEqual(self.calls[0][0][:2], [str(exe), "assemble"])
        self.dotnet.assert_not_called()

    def test_tool_filename_and_existence(self):
        with self.assertRaises(tc.ToolchainError):
            tc.Toolchain(self.root / "missing" / "maji.dll")
        invalid = self.root / "other.dll"
        invalid.write_bytes(b"placeholder")
        with self.assertRaises(tc.ToolchainError):
            tc.Toolchain(invalid)


class CheckoutTests(TemporaryTest):
    def setUp(self):
        super().setUp()
        self.diff = b""
        self.staged = b""
        self.untracked = b""
        self.entries = b"H known.cs\0"
        self.revision = tc.REVISION
        self.contents = b"patched"
        self.git = self.patch("_git", side_effect=self.git_result)
        self.files = {"known.cs": {"baseline_sha256": tc._sha256(b"base"),
                                   "patched_sha256": tc._sha256(b"patched")}}

    def git_result(self, source, *args):
        if args == ("rev-parse", "--show-toplevel"):
            return str(self.root).encode()
        if args == ("rev-parse", "HEAD"):
            return self.revision.encode()
        if args[:2] == ("ls-files", "--others"):
            return self.untracked
        if args[:2] == ("ls-files", "-v"):
            return self.entries
        if args[:2] == ("diff", "--cached"):
            return self.staged
        if args[0] == "diff":
            return self.diff
        if args[0] == "show":
            return self.contents
        self.fail(f"Unexpected git command: {args}")

    def validate(self):
        return tc._validate_checkout(self.root, tc.REVISION, b"fixed patch", self.files)

    def test_clean_checkout(self):
        self.assertEqual(self.validate(), "clean")

    def test_exact_patch_in_checkout_and_index(self):
        self.diff = b"fixed patch"
        self.staged = b"known.cs\0"
        self.assertEqual(self.validate(), "patched")

    def test_wrong_head_rejected(self):
        self.revision = "0" * 40
        with self.assertRaisesRegex(tc.ToolchainError, "HEAD must be"):
            self.validate()

    def test_unknown_or_partial_working_diff_rejected(self):
        self.diff = b"only part of patch"
        with self.assertRaisesRegex(tc.ToolchainError, "Unknown working-tree"):
            self.validate()

    def test_unknown_staged_changes_even_if_worktree_is_clean(self):
        self.staged = b"unknown.cs\0"
        with self.assertRaisesRegex(tc.ToolchainError, "Unknown staged"):
            self.validate()

    def test_unexpected_staged_contents_rejected(self):
        self.staged = b"known.cs\0"
        self.contents = b"unexpected"
        with self.assertRaisesRegex(tc.ToolchainError, "Unexpected staged"):
            self.validate()

    def test_untracked_files_rejected(self):
        self.untracked = b"private.txt\0"
        with self.assertRaisesRegex(tc.ToolchainError, "Untracked"):
            self.validate()

    def test_hidden_or_unmerged_entries_rejected(self):
        for entry in (b"h known.cs\0", b"S known.cs\0", b"M known.cs\0"):
            with self.subTest(entry=entry), self.assertRaises(tc.ToolchainError):
                self.entries = entry
                self.validate()


class ArchiveAndMetadataTests(TemporaryTest):
    def test_vendored_checksums_and_exact_sources(self):
        vendor = tc._vendor_metadata()
        self.assertEqual(vendor["upstream"]["revision"], tc.REVISION)
        self.assertEqual(len(vendor["patch"]["files"]), 3)
        self.assertEqual(vendor["license"]["spdx"], "MIT")
        self.assertEqual(vendor["opcode"]["source_path"], "src/MajiroLib/Script/Opcode.cs")

    def test_archive_extracts_regular_files(self):
        tc._extract_archive(tar_bytes({"src/test.cs": b"synthetic"}), self.root)
        self.assertEqual((self.root / "src" / "test.cs").read_bytes(), b"synthetic")

    def test_archive_rejects_unsafe_paths(self):
        for name in ("../outside", "/outside", "C:/outside", "x\\outside", "x/../outside",
                     "x//outside", "CON", "x/file:stream", "x/file."):
            with self.subTest(name=name), self.assertRaises(tc.ToolchainError):
                tc._extract_archive(tar_bytes({name: b"synthetic"}), self.root)

    def test_archive_rejects_links_and_duplicate_names(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w") as archive:
                    member = tarfile.TarInfo("link")
                    member.type = kind
                    member.linkname = "../outside"
                    archive.addfile(member)
                with self.assertRaises(tc.ToolchainError):
                    tc._extract_archive(buffer.getvalue(), self.root)
        with self.assertRaises(tc.ToolchainError):
            tc._extract_archive(tar_bytes({"same": b"a", "SAME": b"b"}), self.root)

    def manifest(self):
        vendor = tc._vendor_metadata()
        for name in ("maji.dll", "MajiroLib.dll", "maji.deps.json", "maji.runtimeconfig.json", "LICENSE"):
            (self.root / name).write_bytes(b"synthetic " + name.encode())
        return {
            "schema_version": 1, "status": "verified",
            "baseline": {"upstream": vendor["upstream"], "submodules": vendor["submodules"],
                         "archive_sha256": vendor["archive_sha256"]},
            "patch": vendor["patch"],
            "vendor_metadata_sha256": tc._sha256((tc.VENDOR / "metadata.json").read_bytes()),
            "build": {"target_framework": "net7.0", "configuration": "Release", "network": "disabled",
                      "language_version": "11.0", "roll_forward": "LatestMajor"},
            "smoke_tests": {"cp932": "synthetic", "utf8": "synthetic"},
            "files": tc._inventory(self.root),
        }

    def write_manifest(self, manifest):
        (self.root / tc.METADATA_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    def test_verify_toolchain_directory_and_instance(self):
        manifest = self.manifest()
        self.write_manifest(manifest)
        self.assertEqual(tc.verify_toolchain(self.root), manifest)
        self.assertEqual(tc.Toolchain(self.root / "maji.dll").verify(), manifest)

    def test_verify_rejects_changed_missing_or_added_outputs(self):
        for operation in ("changed", "missing", "added"):
            with self.subTest(operation=operation):
                self.write_manifest(self.manifest())
                if operation == "changed":
                    (self.root / "maji.dll").write_bytes(b"changed")
                elif operation == "missing":
                    (self.root / "maji.dll").unlink()
                else:
                    (self.root / "extra.dll").write_bytes(b"added")
                with self.assertRaises(tc.ToolchainError):
                    tc.verify_toolchain(self.root)

    def test_verify_rejects_changed_baseline_patch_or_unsafe_manifest(self):
        original = self.manifest()
        for kind in ("baseline", "patch", "unsafe", "unverified", "framework"):
            manifest = copy.deepcopy(original)
            if kind == "baseline":
                manifest["baseline"]["upstream"]["revision"] = "0" * 40
            elif kind == "patch":
                manifest["patch"]["sha256"] = "0" * 64
            elif kind == "unsafe":
                manifest["files"]["../escape.dll"] = {}
            elif kind == "unverified":
                manifest["status"] = "built"
            else:
                manifest["build"]["target_framework"] = "net10.0"
            with self.subTest(kind=kind), self.assertRaises(tc.ToolchainError):
                self.write_manifest(manifest)
                tc.verify_toolchain(self.root)


class BuildTests(TemporaryTest):
    def test_output_directory_is_never_overwritten_even_when_empty(self):
        output = self.root / "exists"
        output.mkdir()
        with self.assertRaisesRegex(tc.ToolchainError, "Refusing to overwrite"):
            tc.build_toolchain(self.root / "source", output)
        self.assertTrue(output.is_dir())
        self.assertEqual(list(output.iterdir()), [])

    def test_output_parent_must_exist(self):
        with self.assertRaisesRegex(tc.ToolchainError, "parent must already exist"):
            tc.build_toolchain(self.root / "source", self.root / "missing" / "output")

    def test_output_cannot_be_in_source_checkout(self):
        with self.assertRaisesRegex(tc.ToolchainError, "inside the input checkout"):
            tc.build_toolchain(self.root, self.root / "output")

    def test_validation_failure_publishes_nothing(self):
        self.patch("_validate_checkout", side_effect=tc.ToolchainError("wrong HEAD"))
        with self.assertRaisesRegex(tc.ToolchainError, "wrong HEAD"):
            tc.build_toolchain(self.root / "source", self.root / "output")
        self.assertFalse((self.root / "output").exists())

    def test_msbuild_zero_errors_is_not_a_failure(self):
        with patch.object(tc.subprocess, "run", return_value=subprocess.CompletedProcess(
                ["dotnet"], 0, b"Build succeeded.\n    0 Error(s)\n", b"")):
            tc._run(["dotnet"], cwd=self.root, diagnostics=True)

    def build_fixture(self, failure=None):
        source = self.root / "source"
        source.mkdir()
        (source / "sentinel").write_bytes(b"do not modify")
        vendor_dir = self.root / "vendor"
        vendor_dir.mkdir()
        vendor = copy.deepcopy(tc._vendor_metadata())
        vendor["submodules"] = {}
        vendor["patch"]["files"] = {"src/test.cs": {
            "baseline_sha256": tc._sha256(b"base"), "patched_sha256": tc._sha256(b"patched")}}
        archive = tar_bytes({"src/test.cs": b"base", vendor["build"]["project"]: b"<Project/>"})
        vendor["archive_sha256"] = {".": tc._sha256(archive)}
        (vendor_dir / "metadata.json").write_text(json.dumps(vendor), encoding="utf-8")
        (vendor_dir / vendor["patch"]["file"]).write_bytes(b"synthetic patch")
        (vendor_dir / "LICENSE").write_bytes(b"synthetic license")
        dotnet = self.root / "dotnet.exe"
        dotnet.write_bytes(b"synthetic host")
        self.patch("VENDOR", new=vendor_dir)
        self.patch("_vendor_metadata", return_value=vendor)
        self.patch("_dotnet", return_value=str(dotnet))
        self.patch("_validate_checkout", return_value="patched")
        self.patch("_smoke_test", side_effect=tc.ToolchainError("smoke failed") if failure == "smoke" else None,
                   return_value={"cp932": "synthetic", "utf8": "synthetic"})

        def git(checkout, *args):
            if "archive" in args:
                self.assertIn("core.autocrlf=false", args)
                return archive
            if args[0] == "apply":
                if "--check" not in args:
                    (checkout / "src/test.cs").write_bytes(b"patched")
                return b""
            self.fail(f"Unexpected git command: {args}")
        self.patch("_git", side_effect=git)
        commands = []

        def run(args, **kwargs):
            commands.append(args)
            self.assertNotEqual(Path(kwargs["cwd"]), source)
            if args[1] == "--version":
                return b"10.0.403\n"
            if args[1] == "restore":
                config = Path(args[args.index("--configfile") + 1]).read_text(encoding="utf-8")
                self.assertNotIn("https://", config)
                self.assertIn("<clear/>", config)
                self.assertIn("-p:NuGetAudit=false", args)
                self.assertIn("-p:LangVersion=11.0", args)
                self.assertTrue(Path(kwargs["env"]["NUGET_PACKAGES"]).is_relative_to(kwargs["cwd"]))
                if failure == "restore":
                    raise tc.ToolchainError("NU1101: missing offline dependency")
                assets = Path(args[2]).parent / "obj" / "project.assets.json"
                assets.parent.mkdir()
                assets.write_text('{"libraries": {"Synthetic/1.0": {}}}', encoding="utf-8")
            elif args[1] == "build":
                self.assertIn("--no-restore", args)
                self.assertEqual(args[args.index("--framework") + 1], "net7.0")
                self.assertEqual(args[args.index("--configuration") + 1], "Release")
                built = Path(args[args.index("--output") + 1])
                built.mkdir()
                for name in ("maji.dll", "MajiroLib.dll", "maji.deps.json", "maji.runtimeconfig.json"):
                    (built / name).write_bytes(b"synthetic " + name.encode())
            else:
                self.fail(f"Unexpected command: {args}")
            return b""
        self.patch("_run", side_effect=run)
        return source, commands

    def test_full_build_flow_records_and_verifies_files(self):
        source, commands = self.build_fixture()
        output = self.root / "output"
        result = tc.build_toolchain(source, output)
        self.assertEqual(result, output / "maji.dll")
        meta = tc.verify_toolchain(result)
        self.assertEqual(meta["status"], "verified")
        self.assertEqual(meta["build"]["packages"], ["Synthetic/1.0"])
        self.assertEqual([args[1] for args in commands], ["--version", "restore", "build"])
        self.assertEqual(list(source.iterdir()), [source / "sentinel"])
        self.assertEqual((source / "sentinel").read_bytes(), b"do not modify")

    def test_missing_offline_dependency_reports_incomplete_and_no_output(self):
        source, commands = self.build_fixture(failure="restore")
        with self.assertRaisesRegex(tc.ToolchainError, "Offline NuGet restore incomplete"):
            tc.build_toolchain(source, self.root / "output")
        self.assertFalse((self.root / "output").exists())
        self.assertNotIn("build", [args[1] for args in commands])

    def test_failed_smoke_test_prevents_publication(self):
        source, _ = self.build_fixture(failure="smoke")
        with self.assertRaisesRegex(tc.ToolchainError, "smoke failed"):
            tc.build_toolchain(source, self.root / "output")
        self.assertFalse((self.root / "output").exists())


class LocalIntegrationTests(TemporaryTest):
    @unittest.skipUnless(os.environ.get("MAJIRO_TEST_TOOLCHAIN"), "explicit local maji path not supplied")
    def test_existing_local_binary_synthetic_codecs(self):
        result = tc._smoke_test(tc.Toolchain(os.environ["MAJIRO_TEST_TOOLCHAIN"]))
        self.assertEqual(set(result), {"cp932", "utf8"})

    @unittest.skipUnless(os.environ.get("MAJIRO_TEST_SOURCE"), "explicit local source checkout not supplied")
    def test_two_offline_builds_have_identical_artifacts(self):
        source = os.environ["MAJIRO_TEST_SOURCE"]
        first = tc.build_toolchain(source, self.root / "first")
        second = tc.build_toolchain(source, self.root / "second")
        a, b = tc.verify_toolchain(first), tc.verify_toolchain(second)
        self.assertEqual(a["files"], b["files"])
        self.assertEqual(a["smoke_tests"], b["smoke_tests"])


if __name__ == "__main__":
    unittest.main()
