from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from archiveguard import ArchiveGuard, Limits, read_snapshot
from archiveguard.core import GuardFailure, _Budget, _consume, _linked
from archiveguard.demo import corrupt_first_body, make_zip, ordinary, run_demo


ROOT = Path(__file__).resolve().parent.parent


class GuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="archiveguard-test-")
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.destination = self.parent / "new-container"
        self.clean = make_zip([ordinary("docs/a.md", b"hello\n"), ordinary("b.json", b"{}\n")])

    def assertCode(self, report, code, phase=None):
        self.assertEqual(report["outcome"], "rejected")
        self.assertEqual(report["issue"]["code"], code)
        self.assertEqual(report["files"], [])
        self.assertIsNone(report["observed_bytes"])
        if phase:
            self.assertEqual(report["phase"], phase)

    def test_clean_check_is_full_stream_no_filesystem(self):
        with patch("archiveguard.core.tempfile.mkdtemp", side_effect=AssertionError("no disk")):
            report = ArchiveGuard().check(self.clean)
        self.assertEqual(report["outcome"], "verified")
        self.assertEqual(report["observed_bytes"], 9)
        self.assertEqual(report["archive_sha256"], hashlib.sha256(self.clean).hexdigest())
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_extract_publishes_exact_contents_and_hashes(self):
        report = ArchiveGuard().extract(self.clean, self.destination)
        self.assertEqual(report["outcome"], "published")
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), ["payload"])
        for record in report["files"]:
            content = (self.destination / "payload" / record["path"]).read_bytes()
            self.assertEqual(len(content), record["bytes"])
            self.assertEqual(hashlib.sha256(content).hexdigest(), record["sha256"])

    def test_stored_and_deflated_same_content(self):
        members = [ordinary("a.txt", b"hello-world\n" * 20)]
        reports = [ArchiveGuard().check(make_zip(members, compression=method))
                   for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)]
        self.assertTrue(all(r["outcome"] == "verified" for r in reports))
        self.assertEqual(reports[0]["files"], reports[1]["files"])

    def test_utf8_content_is_preserved(self):
        content = "这是原创合成培训材料，不代表合规结论。\n".encode("utf-8")
        result = ArchiveGuard().extract(make_zip([ordinary("chinese.md", content)]), self.destination)
        self.assertEqual(result["outcome"], "published")
        self.assertEqual((self.destination / "payload/chinese.md").read_bytes(), content)

    def test_uppercase_extension_supported_without_renaming(self):
        result = ArchiveGuard().check(make_zip([ordinary("UPPER.MD")]))
        self.assertEqual(result["files"][0]["path"], "UPPER.MD")

    def test_explicit_directory_before_child(self):
        data = make_zip([("docs/", b"", stat.S_IFDIR | 0o700), ordinary("docs/a.txt")])
        self.assertEqual(ArchiveGuard().extract(data, self.destination)["outcome"], "published")

    def test_explicit_directory_after_child(self):
        data = make_zip([ordinary("docs/a.txt"), ("docs/", b"", stat.S_IFDIR | 0o700)])
        self.assertEqual(ArchiveGuard().extract(data, self.destination)["outcome"], "published")

    def test_shared_implicit_directory_allowed(self):
        result = ArchiveGuard().check(make_zip([ordinary("docs/a.txt"), ordinary("docs/b.md")]))
        self.assertEqual(len(result["files"]), 2)

    def test_zero_length_file_allowed(self):
        result = ArchiveGuard().check(make_zip([ordinary("empty.txt", b"")]))
        self.assertEqual(result["outcome"], "verified")
        self.assertEqual(result["observed_bytes"], 0)

    def test_empty_archive_rejected(self):
        self.assertCode(ArchiveGuard().check(make_zip([])), "empty_archive")

    def test_directories_only_rejected(self):
        data = make_zip([("docs/", b"", stat.S_IFDIR | 0o700)])
        self.assertCode(ArchiveGuard().check(data), "empty_archive")

    def test_bad_zip_is_structured_without_exception(self):
        result = ArchiveGuard().check(b"not a zip: synthetic")
        self.assertCode(result, "invalid_archive", "metadata")
        self.assertNotIn("not a zip", json.dumps(result))

    def test_truncated_archive(self):
        self.assertCode(ArchiveGuard().check(self.clean[:-30]), "invalid_archive")

    def test_archive_byte_limit(self):
        result = ArchiveGuard(replace(Limits(), archive_bytes=len(self.clean) - 1)).check(self.clean)
        self.assertCode(result, "archive_limit", "input")
        self.assertIsNone(result["archive_sha256"])

    def test_exact_archive_limit(self):
        result = ArchiveGuard(replace(Limits(), archive_bytes=len(self.clean))).check(self.clean)
        self.assertEqual(result["outcome"], "verified")

    def test_entries_include_directory_records(self):
        data = make_zip([("d/", b"", stat.S_IFDIR | 0o700), ordinary("d/a.md")])
        self.assertCode(ArchiveGuard(replace(Limits(), entries=1)).check(data), "entry_limit")

    def test_declared_file_limit_before_reservation(self):
        with patch("archiveguard.core._reserve", side_effect=AssertionError("not yet")):
            result = ArchiveGuard(replace(Limits(), file_bytes=5)).extract(self.clean, self.destination)
        self.assertCode(result, "file_limit", "metadata")

    def test_declared_total_limit(self):
        self.assertCode(ArchiveGuard(replace(Limits(), total_bytes=8)).check(self.clean), "total_limit")

    def test_exact_declared_limits(self):
        result = ArchiveGuard(replace(Limits(), file_bytes=6, total_bytes=9, entries=2)).check(self.clean)
        self.assertEqual(result["outcome"], "verified")

    def test_ratio_rejects_only_small_repeat_fixture(self):
        data = make_zip([ordinary("repeat.txt", b"a" * 8192)], compression=zipfile.ZIP_DEFLATED)
        self.assertLess(len(data), 1024)
        self.assertCode(ArchiveGuard(replace(Limits(), ratio=10)).check(data), "ratio_limit")

    def test_duplicate_filename(self):
        self.assertCode(ArchiveGuard().check(make_zip([ordinary("a.txt"), ordinary("a.txt")])), "namespace_collision")

    def test_case_collision(self):
        self.assertCode(ArchiveGuard().check(make_zip([ordinary("A.txt"), ordinary("a.txt")])), "namespace_collision")

    def test_directory_prefix_case_collision(self):
        self.assertCode(ArchiveGuard().check(make_zip([ordinary("Dir/a.txt"), ordinary("dir/b.txt")])), "namespace_collision")

    def test_file_then_directory_prefix(self):
        self.assertCode(ArchiveGuard().check(make_zip([ordinary("a.md"), ordinary("a.md/b.txt")])), "namespace_collision")

    def test_directory_prefix_then_file(self):
        self.assertCode(ArchiveGuard().check(make_zip([ordinary("a.md/b.txt"), ordinary("a.md")])), "namespace_collision")

    def test_duplicate_explicit_directory(self):
        data = make_zip([ordinary("d/a.txt"), ("d/", b"", stat.S_IFDIR | 0o700), ("d/", b"", stat.S_IFDIR | 0o700)])
        self.assertCode(ArchiveGuard().check(data), "namespace_collision")

    def test_link_metadata_rejected(self):
        data = make_zip([("link.txt", b"../outside.txt", stat.S_IFLNK | 0o777)])
        self.assertCode(ArchiveGuard().extract(data, self.destination), "member_type")
        self.assertFalse(self.destination.exists())

    def test_fifo_metadata_rejected(self):
        data = make_zip([("fifo.txt", b"", stat.S_IFIFO | 0o600)])
        self.assertCode(ArchiveGuard().check(data), "member_type")

    def test_device_metadata_rejected(self):
        data = make_zip([("device.txt", b"", stat.S_IFCHR | 0o600)])
        self.assertCode(ArchiveGuard().check(data), "member_type")

    def test_directory_mode_requires_slash(self):
        data = make_zip([("dir.txt", b"", stat.S_IFDIR | 0o700)])
        self.assertCode(ArchiveGuard().check(data), "member_type")

    def test_directory_record_cannot_contain_payload(self):
        data = make_zip([("dir/", b"hidden text", stat.S_IFDIR | 0o700), ordinary("a.txt")])
        self.assertCode(ArchiveGuard().check(data), "member_type")

    def test_windows_reparse_attribute(self):
        data = bytearray(make_zip([ordinary("a.txt")]))
        offset = data.index(b"PK\x01\x02")
        attr = struct.unpack_from("<I", data, offset + 38)[0]
        struct.pack_into("<I", data, offset + 38, attr | 0x400)
        self.assertCode(ArchiveGuard().check(bytes(data)), "member_type")

    def test_encryption_bit_rejected_without_password(self):
        data = bytearray(make_zip([ordinary("a.txt")]))
        offset = data.index(b"PK\x01\x02")
        flags = struct.unpack_from("<H", data, offset + 8)[0]
        struct.pack_into("<H", data, offset + 8, flags | 1)
        self.assertCode(ArchiveGuard().check(bytes(data)), "method_policy")

    def test_unsupported_compression_is_not_attempted(self):
        data = bytearray(make_zip([ordinary("a.txt")]))
        offset = data.index(b"PK\x01\x02")
        struct.pack_into("<H", data, offset + 10, 99)
        self.assertCode(ArchiveGuard().check(bytes(data)), "method_policy")

    def test_unsupported_extension(self):
        self.assertCode(ArchiveGuard().check(make_zip([ordinary("inert.exe", b"plain training text")])), "extension_policy")

    def test_nested_zip_extension_not_recursed(self):
        self.assertCode(ArchiveGuard().check(make_zip([ordinary("inner.zip", self.clean)])), "extension_policy")

    def test_disguised_content_not_claimed_safe(self):
        result = ArchiveGuard().check(make_zip([ordinary("looks-like-text.txt", self.clean)]))
        self.assertEqual(result["outcome"], "verified")  # Documented content-validation gap.

    def test_crc_failure_rolls_back_all_files(self):
        result = ArchiveGuard().extract(corrupt_first_body(self.clean), self.destination)
        self.assertCode(result, "invalid_member", "stream")
        self.assertFalse(self.destination.exists())

    def test_later_crc_failure_removes_earlier_verified_file(self):
        data = make_zip([ordinary("first.txt", b"first"), ordinary("later.txt", b"later")])
        bad = data.replace(b"laterPK", b"LaterPK", 1)
        self.assertNotEqual(data, bad)
        result = ArchiveGuard().extract(bad, self.destination)
        self.assertCode(result, "invalid_member", "stream")
        self.assertEqual(result["issue"]["member_index"], 1)
        self.assertFalse(self.destination.exists())

    def test_local_filename_disagreement(self):
        bad = self.clean.replace(b"docs/a.md", b"docs/x.md", 1)
        self.assertCode(ArchiveGuard().check(bad), "invalid_member", "stream")

    def test_existing_empty_directory_not_used(self):
        self.destination.mkdir()
        self.assertCode(ArchiveGuard().extract(self.clean, self.destination), "destination_exists")
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_existing_nonempty_directory_unchanged(self):
        self.destination.mkdir()
        marker = self.destination / "keep.txt"
        marker.write_bytes(b"keep")
        self.assertCode(ArchiveGuard().extract(self.clean, self.destination), "destination_exists")
        self.assertEqual(marker.read_bytes(), b"keep")
        self.assertEqual(len(list(self.destination.iterdir())), 1)

    def test_existing_file_unchanged(self):
        self.destination.write_bytes(b"keep")
        self.assertCode(ArchiveGuard().extract(self.clean, self.destination), "destination_exists")
        self.assertEqual(self.destination.read_bytes(), b"keep")

    def test_missing_parent_not_created(self):
        self.assertCode(ArchiveGuard().extract(self.clean, self.parent / "missing/new"), "destination_policy")
        self.assertFalse((self.parent / "missing").exists())

    def test_destination_reservation_race_preserves_other_owner(self):
        original = Path.mkdir

        def race(path, *args, **kwargs):
            if path == self.destination:
                original(path)
                (path / "keep.txt").write_bytes(b"other owner")
            return original(path, *args, **kwargs)

        with patch("archiveguard.core.Path.mkdir", race):
            self.assertCode(ArchiveGuard().extract(self.clean, self.destination), "destination_exists")
        self.assertEqual((self.destination / "keep.txt").read_bytes(), b"other owner")

    def test_staging_creation_failure_cleans_reserved_container(self):
        with patch("archiveguard.core.tempfile.mkdtemp", side_effect=OSError("synthetic private path")):
            result = ArchiveGuard().extract(self.clean, self.destination)
        self.assertEqual(result["outcome"], "error")
        self.assertEqual(result["issue"]["code"], "io_error")
        self.assertNotIn("synthetic private path", json.dumps(result))
        self.assertFalse(self.destination.exists())

    def test_publish_failure_cleans_pending_files(self):
        with patch("archiveguard.core.os.rename", side_effect=OSError("synthetic rename failure")):
            result = ArchiveGuard().extract(self.clean, self.destination)
        self.assertEqual(result["outcome"], "error")
        self.assertFalse(self.destination.exists())

    def test_no_partial_payload_visible_before_rename(self):
        rename = os.rename

        def observed(source, target):
            self.assertFalse(Path(target).exists())
            self.assertEqual((Path(source) / "docs/a.md").read_bytes(), b"hello\n")
            self.assertEqual((Path(source) / "b.json").read_bytes(), b"{}\n")
            return rename(source, target)

        with patch("archiveguard.core.os.rename", side_effect=observed) as called:
            self.assertEqual(ArchiveGuard().extract(self.clean, self.destination)["outcome"], "published")
        called.assert_called_once()

    def test_cleanup_failure_report_does_not_claim_rollback(self):
        with patch("archiveguard.core.shutil.rmtree", side_effect=OSError("busy")):
            result = ArchiveGuard().extract(corrupt_first_body(self.clean), self.destination)
        self.assertEqual(result["outcome"], "error")
        self.assertEqual(result["issue"]["code"], "cleanup_failed")
        self.assertTrue(self.destination.exists())
        self.assertFalse((self.destination / "payload").exists())

    def test_output_does_not_preserve_executable_mode(self):
        data = make_zip([("a.txt", b"hello", stat.S_IFREG | 0o777)])
        result = ArchiveGuard().extract(data, self.destination)
        self.assertEqual(result["outcome"], "published")
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE((self.destination / "payload/a.txt").stat().st_mode), 0o600)

    def test_rejected_filename_is_digest_not_raw(self):
        name = "../SYNTHETIC_PRIVATE_LABEL.txt"
        result = ArchiveGuard().check(make_zip([ordinary(name)]))
        self.assertNotIn("SYNTHETIC_PRIVATE_LABEL", json.dumps(result))
        self.assertEqual(result["issue"]["name_sha256"], hashlib.sha256(name.encode()).hexdigest())

    def test_nul_retained_in_original_name_is_rejected(self):
        data = make_zip([ordinary("aXb.txt")]).replace(b"aXb.txt", b"a\x00b.txt")
        self.assertCode(ArchiveGuard().check(data), "path_policy")

    def test_path_depth_budget(self):
        self.assertCode(ArchiveGuard(replace(Limits(), depth=1)).check(self.clean), "path_policy")

    def test_path_length_budget(self):
        self.assertCode(ArchiveGuard(replace(Limits(), path_chars=8)).check(self.clean), "path_policy")

    def test_component_length_budget(self):
        self.assertCode(ArchiveGuard(replace(Limits(), component_chars=3)).check(self.clean), "path_policy")

    def test_input_bytearray_refused(self):
        with self.assertRaises(TypeError):
            ArchiveGuard().check(bytearray(self.clean))

    def test_invalid_limit_types_and_values(self):
        for value in (0, -1, True, 1.5, "10", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Limits(entries=value)

    def test_implementation_ceilings(self):
        for setting in ({"archive_bytes": 33 * 1024 * 1024}, {"entries": 4097}, {"depth": 17}, {"path_chars": 181}):
            with self.subTest(setting=setting), self.assertRaises(ValueError):
                Limits(**setting)

    def test_read_bounded_snapshot(self):
        path = self.parent / "input.zip"
        path.write_bytes(self.clean)
        self.assertEqual(read_snapshot(path), self.clean)
        with self.assertRaises(ValueError):
            read_snapshot(path, replace(Limits(), archive_bytes=1))

    def test_snapshot_rejects_directory(self):
        with self.assertRaises(ValueError):
            read_snapshot(self.parent)

    def test_snapshot_growth_detected_after_open(self):
        path = self.parent / "input.zip"
        path.write_bytes(b"x" * 10)
        real_fstat = os.fstat

        def stale_size(fd):
            result = list(real_fstat(fd))
            result[6] = 1
            return os.stat_result(result)

        with patch("archiveguard.core.os.fstat", stale_size), self.assertRaises(ValueError):
            read_snapshot(path, replace(Limits(), archive_bytes=5))

    def test_reparse_detection_without_new_python_junction_api(self):
        class Fake:
            st_mode = stat.S_IFDIR
            st_file_attributes = 0x400
        self.assertTrue(_linked(Fake()))

    def test_parent_reparse_check_is_enforced(self):
        with patch("archiveguard.core._linked", return_value=True):
            self.assertCode(ArchiveGuard().extract(self.clean, self.destination), "destination_policy")
        self.assertFalse(self.destination.exists())

    def test_snapshot_link_refusal_branch(self):
        path = self.parent / "input.zip"
        path.write_bytes(self.clean)
        with patch("archiveguard.core._linked", return_value=True), self.assertRaises(ValueError):
            read_snapshot(path)

    def test_real_parent_symlink_where_supported(self):
        link = self.parent / "linked"
        real = self.parent / "real"
        real.mkdir()
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError:
            self.skipTest("OS/user does not permit creating symlinks; reparse branch tested separately")
        self.assertCode(ArchiveGuard().extract(self.clean, link / "new"), "destination_policy")
        self.assertEqual(list(real.iterdir()), [])

    def test_demo_reproduces_evidence(self):
        self.assertEqual(run_demo()["scenario_count"], 12)


class StreamTests(unittest.TestCase):
    """Injected lying streams exercise observed budgets independently of ZIP declarations."""
    def consume(self, data, *, declared=None, compressed=100, limits=Limits(), used=0):
        info = zipfile.ZipInfo("a.txt")
        info.file_size = len(data) if declared is None else declared
        info.compress_size = compressed
        sink = io.BytesIO()
        budget = _Budget(used)
        return info, sink, budget

    def test_observed_file_limit_before_oversized_write(self):
        limits = replace(Limits(), file_bytes=10)
        info, sink, budget = self.consume(b"x" * 11, declared=1)
        with self.assertRaises(GuardFailure) as caught:
            _consume(io.BytesIO(b"x" * 11), sink, info, limits, budget, 0)
        self.assertEqual(caught.exception.code, "file_limit")
        self.assertLessEqual(len(sink.getvalue()), 10)

    def test_observed_total_budget_shared_between_members(self):
        limits = replace(Limits(), total_bytes=10)
        info, sink, budget = self.consume(b"x" * 6, used=5)
        with self.assertRaises(GuardFailure) as caught:
            _consume(io.BytesIO(b"x" * 6), sink, info, limits, budget, 1)
        self.assertEqual(caught.exception.code, "total_limit")
        self.assertEqual(sink.getvalue(), b"")

    def test_observed_ratio_limit_not_only_metadata(self):
        limits = replace(Limits(), ratio=2)
        info, sink, budget = self.consume(b"x" * 5, declared=1, compressed=2)
        with self.assertRaises(GuardFailure) as caught:
            _consume(io.BytesIO(b"x" * 5), sink, info, limits, budget, 0)
        self.assertEqual(caught.exception.code, "ratio_limit")
        self.assertEqual(sink.getvalue(), b"")

    def test_short_stream_mismatches_declared_size(self):
        info, sink, budget = self.consume(b"x", declared=2)
        with self.assertRaises(GuardFailure) as caught:
            _consume(io.BytesIO(b"x"), sink, info, Limits(), budget, 0)
        self.assertEqual(caught.exception.code, "size_mismatch")

    def test_long_stream_mismatches_declared_size(self):
        info, sink, budget = self.consume(b"xx", declared=1)
        with self.assertRaises(GuardFailure) as caught:
            _consume(io.BytesIO(b"xx"), sink, info, Limits(), budget, 0)
        self.assertEqual(caught.exception.code, "size_mismatch")

    def test_exact_observed_limit_requires_final_eof_read(self):
        data = b"x" * 10
        info, sink, budget = self.consume(data, compressed=10)
        result = _consume(io.BytesIO(data), sink, info, replace(Limits(), file_bytes=10, total_bytes=10, ratio=1), budget, 0)
        self.assertEqual(result, (10, hashlib.sha256(data).hexdigest()))

    def test_read_request_is_bounded(self):
        class Observed(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= 65536:
                    raise AssertionError("unbounded read")
                return super().read(size)
        data = b"x" * 200000
        info, sink, budget = self.consume(data, compressed=len(data))
        self.assertEqual(_consume(Observed(data), None, info, Limits(), budget, 0)[0], len(data))

    def test_late_read_failure_propagates_not_success(self):
        class Broken(io.BytesIO):
            def read(self, size=-1):
                if self.tell():
                    raise zipfile.BadZipFile("synthetic")
                return super().read(1)
        info, sink, budget = self.consume(b"xx")
        with self.assertRaises(zipfile.BadZipFile):
            _consume(Broken(b"xx"), sink, info, Limits(), budget, 0)


class CLITests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, "-S", "-X", "utf8", "-m", "archiveguard", *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30)

    def test_check_cli_success(self):
        with tempfile.TemporaryDirectory() as parent:
            source = Path(parent) / "bundle.zip"
            source.write_bytes(make_zip([ordinary("a.txt")]))
            result = self.invoke("check", source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["outcome"], "verified")

    def test_check_cli_rejection(self):
        with tempfile.TemporaryDirectory() as parent:
            source = Path(parent) / "bundle.zip"
            source.write_bytes(make_zip([ordinary("../outside.txt")]))
            result = self.invoke("check", source)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["issue"]["code"], "path_policy")
            self.assertNotIn("../outside", result.stdout + result.stderr)

    def test_missing_input_cli_error_no_local_path_echo(self):
        result = self.invoke("check", "SYNTHETIC_MISSING_PRIVATE.zip")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["outcome"], "error")
        self.assertNotIn("SYNTHETIC_MISSING_PRIVATE", result.stdout + result.stderr)

    def test_invalid_policy_cli_error(self):
        result = self.invoke("check", "unused.zip", "--entries", "0")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["phase"], "local_input")

    def test_extract_cli_publishes(self):
        with tempfile.TemporaryDirectory() as parent:
            source, target = Path(parent) / "bundle.zip", Path(parent) / "new"
            source.write_bytes(make_zip([ordinary("a.txt")]))
            result = self.invoke("extract", source, target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((target / "payload/a.txt").is_file())

    def test_check_cli_override_is_effective(self):
        with tempfile.TemporaryDirectory() as parent:
            source = Path(parent) / "bundle.zip"
            source.write_bytes(make_zip([ordinary("a.txt", b"xx")]))
            result = self.invoke("check", source, "--file-bytes", "1")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["issue"]["code"], "file_limit")

    def test_demo_cli(self):
        result = self.invoke("demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["scenario_count"], 12)


BAD_PATHS = {
    "parent": "../outside.txt", "nested_parent": "safe/../../outside.txt",
    "absolute": "/absolute.txt", "drive": "C:/file.txt", "drive_relative": "C:file.txt",
    "backslash": "safe\\file.txt", "unc": "\\\\server\\file.txt", "doubled_slash": "safe//a.txt",
    "dot": "./a.txt", "dot_segment": "safe/./a.txt", "reserved": "CON.txt",
    "reserved_extension": "NUL.tar.txt", "reserved_dir": "lpt1/a.txt",
    "trailing_dot": "safe./a.txt", "trailing_space": "safe /a.txt", "ads": "a.txt:stream",
    "wildcard": "a?.txt", "quote": 'a".txt', "control": "a\x1b.txt",
    "unicode": "中文.md", "bidi": "a\u202e.txt", "tilde_alias": "ABCDEF~1.txt",
    "percent_encoded": "%2e%2e/a.txt", "leading_dot": ".hidden/a.txt", "leading_dash": "-option.txt",
}


def path_test(name):
    def test(self):
        data = make_zip([ordinary(name)])
        result = ArchiveGuard().extract(data, self.destination)
        self.assertCode(result, "path_policy", "metadata")
        self.assertFalse(self.destination.exists())
        self.assertFalse((self.parent / "outside.txt").exists())
    return test


for case, name in BAD_PATHS.items():
    setattr(GuardTests, "test_path_" + case, path_test(name))


if __name__ == "__main__":
    unittest.main()
