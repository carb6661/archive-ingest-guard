"""Never execute archive contents; never merge into an existing directory."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import BinaryIO
import zipfile
import zlib


PROFILE = "portable-document-quarantine-v1"
SUFFIXES = (".md", ".txt", ".json", ".csv")
COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z", re.ASCII)
DEVICES = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{n}" for prefix in ("com", "lpt") for n in range(10)
}


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 2 * 1024 * 1024
    entries: int = 128
    file_bytes: int = 4 * 1024 * 1024
    total_bytes: int = 16 * 1024 * 1024
    ratio: int = 100
    depth: int = 8
    path_chars: int = 180
    component_chars: int = 80

    def __post_init__(self) -> None:
        # Avoid bool-as-int and accidental disabling by zero/negative values.
        for value in asdict(self).values():
            if type(value) is not int or value <= 0:
                raise ValueError("limits must be positive integers")
        if self.archive_bytes > 32 * 1024 * 1024:
            raise ValueError("archive_bytes exceeds this implementation's 32 MiB ceiling")
        if self.entries > 4096 or self.depth > 16 or self.path_chars > 180:
            raise ValueError("entry/depth/path limits exceed implementation ceilings")


ADVICE = {
    "archive_limit": "Reduce the upload size; do not just increase the decompression budget.",
    "entry_limit": "Split the bundle into fewer business-required documents.",
    "empty_archive": "Supply at least one document, not only directories.",
    "path_policy": "Use relative ASCII document paths with no dot segments, aliases or reserved names.",
    "namespace_collision": "Rename colliding entries and file/directory prefixes explicitly.",
    "member_type": "Only ordinary files and empty directory records are accepted; remove link/device attributes.",
    "method_policy": "Re-export as unencrypted ZIP_STORED or ZIP_DEFLATED.",
    "extension_policy": "Only .md, .txt, .json and .csv are accepted into quarantine; content is still untrusted.",
    "file_limit": "Split the document to meet the per-file byte budget.",
    "total_limit": "Reduce the total decompressed content size.",
    "ratio_limit": "Review unusually compressible data; absolute size limits still apply.",
    "invalid_archive": "Re-export the archive with a maintained ZIP tool; do not bypass verification.",
    "invalid_member": "Check local headers, CRC, overlap and stream integrity; re-export rather than bypass.",
    "size_mismatch": "Re-export the member; declared and observed sizes must agree.",
    "destination_exists": "Choose a new destination container; existing paths are never merged or deleted.",
    "destination_policy": "Use an existing, trusted, local parent directory without symlinks or reparse points.",
    "io_error": "Check private workspace permissions, path length and free space; retry in a new container.",
    "cleanup_failed": "A newly reserved incomplete container may remain; inspect it locally before removing it.",
}


class GuardFailure(Exception):
    def __init__(self, code: str, phase: str, index: int | None = None, name: str | None = None):
        super().__init__(code)  # Never expose a parser exception or raw rejected filename.
        self.code, self.phase, self.index = code, phase, index
        self.name_sha256 = (
            hashlib.sha256(name.encode("utf-8", errors="surrogatepass")).hexdigest()
            if name is not None else None
        )


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def read_snapshot(path: str | Path, limits: Limits = Limits()) -> bytes:
    """Bounded immutable copy. Local input/ancestors must not be concurrently replaced."""
    candidate = Path(path)
    info = candidate.lstat()
    if _linked(info) or not stat.S_ISREG(info.st_mode):
        raise ValueError("input must be a regular file, not a link or reparse point")
    with candidate.open("rb") as source:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > limits.archive_bytes:
            raise ValueError("input exceeds archive byte limit or is not a regular file")
        data = source.read(limits.archive_bytes + 1)
    if len(data) > limits.archive_bytes:
        raise ValueError("input exceeds archive byte limit")
    return data


def _path(info: zipfile.ZipInfo, limits: Limits, index: int) -> tuple[str, bool]:
    name = info.orig_filename
    reject = lambda: GuardFailure("path_policy", "metadata", index, name)
    # orig_filename retains NULs that ZipInfo.filename may already have truncated.
    if name != info.filename or not name or len(name) > limits.path_chars:
        raise reject()
    is_dir = name.endswith("/")
    path = name[:-1] if is_dir else name
    parts = path.split("/")
    if len(parts) > limits.depth:
        raise reject()
    for part in parts:
        if (
            not COMPONENT.fullmatch(part)
            or part in (".", "..")
            or len(part) > limits.component_chars
            or part.endswith(".")
            or part.split(".")[0].lower() in DEVICES
        ):
            raise reject()
    return path, is_dir


def _plan(archive: zipfile.ZipFile, limits: Limits) -> list[tuple[zipfile.ZipInfo, str, bool]]:
    infos = archive.infolist()  # zipfile parses the central directory before our entry cap.
    if len(infos) > limits.entries:
        raise GuardFailure("entry_limit", "metadata")
    seen: set[str] = set()
    namespace: dict[str, tuple[str, bool]] = {}
    result = []
    total = files = 0
    for index, info in enumerate(infos):
        name, is_dir = _path(info, limits, index)
        fail = lambda code: GuardFailure(code, "metadata", index, info.orig_filename)
        file_type = stat.S_IFMT(info.external_attr >> 16)
        expected = stat.S_IFDIR if is_dir else stat.S_IFREG
        if (
            file_type not in (0, expected)
            or (info.external_attr & 0x400)  # Windows reparse attribute (if present).
            or (info.external_attr & 0x08)  # DOS volume label.
            or (not is_dir and info.external_attr & 0x10)
            or (is_dir and (info.file_size != 0 or info.CRC != 0))
        ):
            raise fail("member_type")
        if info.flag_bits & (0x01 | 0x40) or info.compress_type not in (
            zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED
        ):
            raise fail("method_policy")
        key = name.lower()
        if key in seen:
            raise fail("namespace_collision")
        seen.add(key)
        parts = name.split("/")
        for position in range(len(parts)):
            prefix = "/".join(parts[:position + 1])
            directory = position < len(parts) - 1 or is_dir
            prior = namespace.get(prefix.lower())
            if prior is not None and prior != (prefix, directory):
                raise fail("namespace_collision")
            namespace[prefix.lower()] = (prefix, directory)
        if not is_dir:
            files += 1
            if Path(name).suffix.lower() not in SUFFIXES:
                raise fail("extension_policy")
            if info.file_size > limits.file_bytes:
                raise fail("file_limit")
            total += info.file_size
            if total > limits.total_bytes:
                raise fail("total_limit")
            if info.file_size > max(1, info.compress_size) * limits.ratio:
                raise fail("ratio_limit")
        result.append((info, name, is_dir))
    if not files:
        raise GuardFailure("empty_archive", "metadata")
    return result


@dataclass
class _Budget:
    total: int = 0


def _consume(
    source: BinaryIO, sink: BinaryIO | None, info: zipfile.ZipInfo,
    limits: Limits, budget: _Budget, index: int,
) -> tuple[int, str]:
    """Budget observed bytes BEFORE writing; +1 read detects a breached boundary."""
    count = 0
    digest = hashlib.sha256()
    ratio_cap = max(1, info.compress_size) * limits.ratio
    while True:
        remaining = min(limits.file_bytes - count, limits.total_bytes - budget.total, ratio_cap - count)
        block = source.read(min(64 * 1024, remaining + 1))
        if not block:
            break
        count += len(block)
        budget.total += len(block)
        for breached, code in (
            (count > limits.file_bytes, "file_limit"),
            (budget.total > limits.total_bytes, "total_limit"),
            (count > ratio_cap, "ratio_limit"),
        ):
            if breached:
                raise GuardFailure(code, "stream", index, info.orig_filename)
        digest.update(block)
        if sink is not None:
            sink.write(block)
    if count != info.file_size:
        raise GuardFailure("size_mismatch", "stream", index, info.orig_filename)
    return count, digest.hexdigest()


def _reserve(destination: Path) -> Path:
    """Exclusively reserve a new container. Not a hostile-local-writer sandbox."""
    if destination.anchor.startswith("\\\\"):
        raise GuardFailure("destination_policy", "destination")
    for parent in (destination.parent, *destination.parent.parents):
        try:
            info = parent.lstat()
        except OSError:
            raise GuardFailure("destination_policy", "destination") from None
        if _linked(info) or not stat.S_ISDIR(info.st_mode):
            raise GuardFailure("destination_policy", "destination")
    try:
        destination.mkdir(mode=0o700)  # No exist_ok: even an empty pre-existing dir is refused.
    except FileExistsError:
        raise GuardFailure("destination_exists", "destination") from None
    return destination


class ArchiveGuard:
    def __init__(self, limits: Limits = Limits()):
        if not isinstance(limits, Limits):
            raise TypeError("limits must be Limits")
        self.limits = limits

    def check(self, data: bytes) -> dict:
        """Full bounded stream/CRC check without writing extracted files."""
        return self._run(data, None)

    def extract(self, data: bytes, destination: str | Path) -> dict:
        """Publish ONLY destination/payload after all files verify. Never merge."""
        return self._run(data, Path(os.path.abspath(destination)))

    def _run(self, data: bytes, destination: Path | None) -> dict:
        if type(data) is not bytes:
            raise TypeError("data must be immutable bytes")
        report = {
            "schema_version": 1, "profile": PROFILE, "limits": asdict(self.limits),
            "operation": "check" if destination is None else "extract",
            "archive_sha256": None, "archive_bytes": len(data),
            "outcome": "rejected", "phase": "input", "files": [],
            "observed_bytes": None, "issue": None,
        }
        owned: Path | None = None
        published = False
        try:
            if len(data) > self.limits.archive_bytes:
                raise GuardFailure("archive_limit", "input")
            report["archive_sha256"] = hashlib.sha256(data).hexdigest()
            try:
                archive = zipfile.ZipFile(io.BytesIO(data))
            except (zipfile.BadZipFile, UnicodeError, ValueError, NotImplementedError):
                raise GuardFailure("invalid_archive", "metadata") from None
            with archive:
                plan = _plan(archive, self.limits)
                staging: Path | None = None
                if destination is not None:
                    owned = _reserve(destination)
                    staging = Path(tempfile.mkdtemp(prefix=".pending-", dir=owned))
                budget = _Budget()
                records = []
                for index, (info, name, is_dir) in enumerate(plan):
                    target = staging.joinpath(*name.split("/")) if staging else None
                    if is_dir:
                        if target:
                            target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        # Opening empty directory records also checks local header names.
                    elif target:
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    try:
                        with archive.open(info, "r") as source:
                            if target is not None and not is_dir:
                                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                                with os.fdopen(fd, "wb") as sink:
                                    count, digest = _consume(source, sink, info, self.limits, budget, index)
                            else:
                                count, digest = _consume(source, None, info, self.limits, budget, index)
                    except (zipfile.BadZipFile, EOFError, zlib.error, RuntimeError, NotImplementedError, UnicodeError):
                        raise GuardFailure("invalid_member", "stream", index, info.orig_filename) from None
                    if not is_dir:
                        records.append({"index": index, "path": name, "bytes": count, "sha256": digest})
                if owned is not None:
                    # payload did not exist: the whole container was exclusively reserved.
                    os.rename(staging, owned / "payload")
                    published = True
                report.update(
                    outcome="verified" if destination is None else "published",
                    phase="verified" if destination is None else "published",
                    files=records, observed_bytes=budget.total,
                )
        except GuardFailure as failure:
            report.update(phase=failure.phase, issue={
                "code": failure.code, "member_index": failure.index,
                "name_sha256": failure.name_sha256, "advice": ADVICE[failure.code],
            })
        except OSError:
            report.update(outcome="error", phase="io", issue={
                "code": "io_error", "member_index": None, "name_sha256": None, "advice": ADVICE["io_error"],
            })
        finally:
            if owned is not None and not published:
                try:
                    shutil.rmtree(owned)  # Only a container CREATED by this invocation.
                except OSError:
                    report.update(outcome="error", phase="cleanup", issue={
                        "code": "cleanup_failed", "member_index": None,
                        "name_sha256": None, "advice": ADVICE["cleanup_failed"],
                    })
        return report
