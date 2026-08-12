"""Bounded, non-executing readers for Python source package archives."""

from __future__ import annotations

import hashlib
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .extractor import ExtractorLimits, PythonExtractor
from .types import FileAnalysis


class UnsafeArchiveError(ValueError):
    """The archive violates a resource or path safety invariant."""


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_archive_bytes: int = 50_000_000
    max_members: int = 20_000
    max_member_bytes: int = 1_000_000
    max_python_bytes: int = 50_000_000
    max_total_uncompressed_bytes: int = 500_000_000
    max_compression_ratio: float = 250.0
    max_path_bytes: int = 512

    def validate(self) -> None:
        values = (
            self.max_archive_bytes,
            self.max_members,
            self.max_member_bytes,
            self.max_python_bytes,
            self.max_total_uncompressed_bytes,
            self.max_path_bytes,
        )
        if any(value < 1 for value in values):
            raise ValueError("archive limits must be positive")
        if self.max_compression_ratio <= 1.0:
            raise ValueError("max_compression_ratio must exceed one")


@dataclass(frozen=True, slots=True)
class SourceMember:
    path: str
    payload: bytes
    truncated: bool


@dataclass(frozen=True, slots=True)
class ArchiveContents:
    archive_sha256: str
    archive_bytes: int
    archive_format: str
    members_seen: int
    sources: tuple[SourceMember, ...]
    warnings: tuple[str, ...]

    @property
    def python_bytes(self) -> int:
        return sum(len(source.payload) for source in self.sources)


def load_python_archive(
    path: str | Path,
    limits: ArchiveLimits | None = None,
) -> ArchiveContents:
    """Read bounded .py members without extracting or executing the archive."""

    limits = limits or ArchiveLimits()
    limits.validate()
    archive_path = Path(path)
    info = archive_path.lstat()
    if archive_path.is_symlink():
        raise UnsafeArchiveError("archive path cannot be a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeArchiveError("archive path must be a regular file")
    if info.st_size > limits.max_archive_bytes:
        raise UnsafeArchiveError(f"archive exceeds {limits.max_archive_bytes} bytes")
    name = archive_path.name.lower()
    digest = _file_sha256(archive_path)
    if name.endswith((".whl", ".zip")):
        sources, members, warnings = _load_zip(
            archive_path,
            info.st_size,
            limits,
        )
        archive_format = "zip"
    elif name.endswith((".tar.gz", ".tgz")):
        sources, members, warnings = _load_tar(
            archive_path,
            info.st_size,
            limits,
        )
        archive_format = "tar-gzip"
    else:
        raise UnsafeArchiveError("supported archives are wheel, zip, tar.gz, tgz")
    return ArchiveContents(
        archive_sha256=digest,
        archive_bytes=info.st_size,
        archive_format=archive_format,
        members_seen=members,
        sources=tuple(sources),
        warnings=tuple(warnings),
    )


def analyze_sources(
    sources: tuple[SourceMember, ...],
    *,
    enable_dataflow: bool,
    max_events: int = 2_000,
) -> list[FileAnalysis]:
    """Parse source bytes with the normal AST frontend; never import them."""

    extractor = PythonExtractor(
        ExtractorLimits(
            max_file_bytes=max(
                (len(source.payload) for source in sources),
                default=1,
            ),
            max_events=max_events,
        ),
        enable_dataflow=enable_dataflow,
    )
    analyses = []
    for source in sources:
        result = extractor.analyze_source(
            source.payload.decode("utf-8", errors="replace"),
            source.path,
        )
        result.sha256 = hashlib.sha256(source.payload).hexdigest()
        result.bytes_read = len(source.payload)
        result.truncated = source.truncated
        analyses.append(result)
    return analyses


def _load_zip(
    path: Path,
    archive_bytes: int,
    limits: ArchiveLimits,
) -> tuple[list[SourceMember], int, list[str]]:
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > limits.max_members:
                raise UnsafeArchiveError(
                    f"archive exceeds {limits.max_members} members"
                )
            _validate_zip_inventory(members, archive_bytes, limits)
            return _read_zip_sources(archive, members, limits)
    except UnsafeArchiveError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise UnsafeArchiveError(f"cannot read zip archive: {error}") from error


def _validate_zip_inventory(
    members: list[zipfile.ZipInfo],
    archive_bytes: int,
    limits: ArchiveLimits,
) -> None:
    seen: set[str] = set()
    total_uncompressed = 0
    for member in members:
        name = _validated_member_name(member.filename, limits)
        key = name.casefold()
        if key in seen:
            raise UnsafeArchiveError("archive contains duplicate member paths")
        seen.add(key)
        if member.file_size < 0 or member.compress_size < 0:
            raise UnsafeArchiveError("archive contains a negative member size")
        total_uncompressed += member.file_size
        if total_uncompressed > limits.max_total_uncompressed_bytes:
            raise UnsafeArchiveError("archive uncompressed-size limit exceeded")
        if member.flag_bits & 0x1:
            raise UnsafeArchiveError("encrypted archive members are unsupported")
        if (
            name.lower().endswith(".py")
            and member.file_size > 4_096
            and member.file_size / max(1, member.compress_size)
            > limits.max_compression_ratio
        ):
            raise UnsafeArchiveError("Python member compression ratio is unsafe")
    if (
        total_uncompressed > 4_096
        and total_uncompressed / max(1, archive_bytes) > limits.max_compression_ratio
    ):
        raise UnsafeArchiveError("archive compression ratio is unsafe")


def _read_zip_sources(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    limits: ArchiveLimits,
) -> tuple[list[SourceMember], int, list[str]]:
    sources: list[SourceMember] = []
    warnings: list[str] = []
    python_bytes = 0
    truncated = 0
    special = 0
    budget_exhausted = False
    for member in members:
        name = _validated_member_name(member.filename, limits)
        if member.is_dir() or not name.lower().endswith(".py"):
            continue
        mode = (member.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if file_type and file_type != stat.S_IFREG:
            special += 1
            continue
        budget = min(member.file_size, limits.max_member_bytes)
        if python_bytes + budget > limits.max_python_bytes:
            budget_exhausted = True
            continue
        with archive.open(member, "r") as handle:
            payload = handle.read(limits.max_member_bytes + 1)
        was_truncated = (
            member.file_size > limits.max_member_bytes
            or len(payload) > limits.max_member_bytes
        )
        payload = payload[: limits.max_member_bytes]
        if not was_truncated and len(payload) != member.file_size:
            raise UnsafeArchiveError("zip member size does not match its metadata")
        truncated += int(was_truncated)
        python_bytes += len(payload)
        sources.append(SourceMember(name, payload, was_truncated))
    if special:
        warnings.append(f"special-members-skipped:{special}")
    if truncated:
        warnings.append(f"python-members-truncated:{truncated}")
    if budget_exhausted:
        warnings.append("python-byte-limit-reached")
    return sources, len(members), warnings


def _load_tar(
    path: Path,
    archive_bytes: int,
    limits: ArchiveLimits,
) -> tuple[list[SourceMember], int, list[str]]:
    sources: list[SourceMember] = []
    warnings: list[str] = []
    seen: set[str] = set()
    members_seen = 0
    total_uncompressed = 0
    python_bytes = 0
    special = 0
    truncated = 0
    budget_exhausted = False
    try:
        with tarfile.open(path, mode="r|gz") as archive:
            for member in archive:
                members_seen += 1
                if members_seen > limits.max_members:
                    raise UnsafeArchiveError(
                        f"archive exceeds {limits.max_members} members"
                    )
                name = _validated_member_name(member.name, limits)
                key = name.casefold()
                if key in seen:
                    raise UnsafeArchiveError("archive contains duplicate member paths")
                seen.add(key)
                if member.size < 0:
                    raise UnsafeArchiveError("archive contains a negative member size")
                if member.isfile():
                    total_uncompressed += member.size
                if total_uncompressed > limits.max_total_uncompressed_bytes:
                    raise UnsafeArchiveError("archive uncompressed-size limit exceeded")
                if not member.isfile():
                    if name.lower().endswith(".py"):
                        special += 1
                    continue
                if not name.lower().endswith(".py"):
                    continue
                budget = min(member.size, limits.max_member_bytes)
                if python_bytes + budget > limits.max_python_bytes:
                    budget_exhausted = True
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    raise UnsafeArchiveError("cannot read regular tar member")
                payload = handle.read(limits.max_member_bytes + 1)
                was_truncated = (
                    member.size > limits.max_member_bytes
                    or len(payload) > limits.max_member_bytes
                )
                payload = payload[: limits.max_member_bytes]
                if not was_truncated and len(payload) != member.size:
                    raise UnsafeArchiveError(
                        "tar member size does not match its metadata"
                    )
                truncated += int(was_truncated)
                python_bytes += len(payload)
                sources.append(SourceMember(name, payload, was_truncated))
    except UnsafeArchiveError:
        raise
    except (EOFError, OSError, tarfile.TarError) as error:
        raise UnsafeArchiveError(f"cannot read tar archive: {error}") from error
    if (
        total_uncompressed > 4_096
        and total_uncompressed / max(1, archive_bytes) > limits.max_compression_ratio
    ):
        raise UnsafeArchiveError("archive compression ratio is unsafe")
    if special:
        warnings.append(f"special-members-skipped:{special}")
    if truncated:
        warnings.append(f"python-members-truncated:{truncated}")
    if budget_exhausted:
        warnings.append("python-byte-limit-reached")
    return sources, members_seen, warnings


def _validated_member_name(name: str, limits: ArchiveLimits) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise UnsafeArchiveError("archive contains an invalid member path")
    if len(name.encode("utf-8", errors="surrogatepass")) > limits.max_path_bytes:
        raise UnsafeArchiveError("archive member path is too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise UnsafeArchiveError("archive member path contains control characters")
    pure = PurePosixPath(name)
    if (
        not pure.parts
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise UnsafeArchiveError("archive member path escapes its logical root")
    return pure.as_posix()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()
