"""Tiny synthetic metadata cases, never exploit a real target or extract unsafe paths."""

from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import tempfile
import warnings
import zipfile

from .core import ArchiveGuard, Limits


SAMPLE = b"# Synthetic control\n\nThis is a fictional training document, not a compliance claim.\n"
MANIFEST = b'{"dataset":"synthetic","owner":"training-team"}\n'


def make_zip(entries, *, compression=zipfile.ZIP_STORED) -> bytes:
    """Fixture builder for small in-memory samples; no filesystem path extraction."""
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # Duplicate names are an intentional fixture.
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content, mode in entries:
                info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                # ZipInfo can normalize the OS separator on Windows. Keep the
                # fixture's EXACT raw header name, so cross-platform tests test
                # the same input rather than silently repairing the bad sample.
                info.filename = info.orig_filename = name
                info.create_system = 3
                info.compress_type = compression
                info.external_attr = (mode << 16) | (0x10 if name.endswith("/") else 0)
                archive.writestr(info, content)
    return buffer.getvalue()


def ordinary(name, content=b"synthetic\n"):
    return name, content, stat.S_IFREG | 0o600


def corrupt_first_body(data: bytes) -> bytes:
    """Flip ONE byte of a tiny stored fixture to exercise CRC rollback."""
    name_length, extra_length = struct.unpack_from("<HH", data, 26)
    offset = 30 + name_length + extra_length
    altered = bytearray(data)
    altered[offset] ^= 1
    return bytes(altered)


def run_demo() -> dict:
    clean = make_zip([ordinary("controls/access.md", SAMPLE), ordinary("manifest.json", MANIFEST)])
    base = Limits()
    cases = [
        ("before-parent-path", make_zip([ordinary("../outside.txt")]), base, "path_policy"),
        ("after-clean-bundle", clean, base, None),
        ("case-alias", make_zip([ordinary("A.txt"), ordinary("a.txt")]), base, "namespace_collision"),
        ("prefix-alias", make_zip([ordinary("Docs/a.txt"), ordinary("docs/b.txt")]), base, "namespace_collision"),
        ("symlink-metadata", make_zip([("link.txt", b"../outside.txt", stat.S_IFLNK | 0o777)]), base, "member_type"),
        ("unsupported-extension", make_zip([ordinary("run.py", b"# inert text, never executed\n")]), base, "extension_policy"),
        ("file-budget", make_zip([ordinary("a.txt", b"x" * 33)]), replace(base, file_bytes=32), "file_limit"),
        ("total-budget", make_zip([ordinary("a.txt", b"x" * 20), ordinary("b.txt", b"x" * 20)]), replace(base, total_bytes=32), "total_limit"),
        ("entry-budget", clean, replace(base, entries=1), "entry_limit"),
        ("ratio-budget", make_zip([ordinary("repeat.txt", b"x" * 8192)], compression=zipfile.ZIP_DEFLATED), replace(base, ratio=10), "ratio_limit"),
        ("corrupt-stream", corrupt_first_body(clean), base, "invalid_member"),
    ]
    summaries = []
    with tempfile.TemporaryDirectory(prefix="archiveguard-demo-") as directory:
        parent = Path(directory)
        for name, data, limits, expected in cases:
            destination = parent / name
            result = ArchiveGuard(limits).extract(data, destination)
            code = result["issue"]["code"] if result["issue"] else None
            success = expected is None
            assert code == expected, (name, code, expected)
            assert result["outcome"] == ("published" if success else "rejected"), name
            assert destination.exists() == success, name
            assert not (parent / "outside.txt").exists()
            if success:
                assert (destination / "payload/controls/access.md").read_bytes() == SAMPLE
                assert (destination / "payload/manifest.json").read_bytes() == MANIFEST
            summaries.append({
                "scenario": name, "outcome": result["outcome"], "phase": result["phase"],
                "issue_code": code, "destination_exists": destination.exists(),
                "verified_files": len(result["files"]), "observed_bytes": result["observed_bytes"],
            })
        # Independently establish that a pre-existing container is not merged or deleted.
        existing = parent / "existing"
        existing.mkdir()
        marker = existing / "keep.txt"
        marker.write_bytes(b"synthetic pre-existing marker\n")
        rejected = ArchiveGuard().extract(clean, existing)
        assert rejected["issue"]["code"] == "destination_exists"
        assert marker.read_bytes() == b"synthetic pre-existing marker\n"
        summaries.append({
            "scenario": "existing-container", "outcome": rejected["outcome"],
            "phase": rejected["phase"], "issue_code": "destination_exists",
            "destination_exists": True, "verified_files": 0, "observed_bytes": None,
        })
    result = {
        "dataset": "original-small-synthetic-v1", "scenario_count": len(summaries),
        "clean_content_sha256": hashlib.sha256(SAMPLE + MANIFEST).hexdigest(),
        "scenarios": summaries,
        "note": "No unsafe baseline extractor runs; before/after changes the bundle, not the trust policy.",
    }
    expected_path = Path(__file__).resolve().parent.parent / "examples/expected.json"
    assert expected_path.is_file(), "checked-in demo evidence is missing"
    assert result == json.loads(expected_path.read_text(encoding="utf-8")), "checked-in demo evidence drift"
    return result
