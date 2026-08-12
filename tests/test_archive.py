import io
import stat
import tarfile
import zipfile

import pytest

from malir.archive import (
    ArchiveLimits,
    UnsafeArchiveError,
    analyze_sources,
    load_python_archive,
)


def _write_zip(path, members):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members:
            archive.writestr(name, payload)


def test_zip_source_is_parsed_but_never_executed(tmp_path):
    marker = tmp_path / "executed"
    archive_path = tmp_path / "sample.whl"
    source = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
    _write_zip(archive_path, [("package/__init__.py", source)])

    contents = load_python_archive(archive_path)
    analyses = analyze_sources(contents.sources, enable_dataflow=True)

    assert contents.archive_format == "zip"
    assert len(contents.archive_sha256) == 64
    int(contents.archive_sha256, 16)
    assert contents.members_seen == 1
    assert len(analyses) == 1
    assert analyses[0].parse_error is None
    assert not marker.exists()


def test_zip_rejects_traversal_and_duplicate_paths(tmp_path):
    traversal = tmp_path / "traversal.zip"
    _write_zip(traversal, [("../escape.py", "print('never run')")])
    with pytest.raises(UnsafeArchiveError, match="logical root"):
        load_python_archive(traversal)

    duplicate = tmp_path / "duplicate.zip"
    _write_zip(
        duplicate,
        [
            ("Package/main.py", "x = 1"),
            ("package/MAIN.py", "x = 2"),
        ],
    )
    with pytest.raises(UnsafeArchiveError, match="duplicate"):
        load_python_archive(duplicate)


def test_zip_skips_symlink_members(tmp_path):
    archive_path = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("package/link.py")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(link, "target.py")
    contents = load_python_archive(archive_path)

    assert contents.sources == ()
    assert contents.warnings == ("special-members-skipped:1",)


def test_zip_enforces_member_count_and_compression_ratio(tmp_path):
    members = tmp_path / "members.zip"
    _write_zip(members, [("one.py", "x = 1"), ("two.py", "x = 2")])
    with pytest.raises(UnsafeArchiveError, match="members"):
        load_python_archive(members, ArchiveLimits(max_members=1))

    compressed = tmp_path / "compressed.zip"
    _write_zip(compressed, [("payload.py", "#" * 100_000)])
    with pytest.raises(UnsafeArchiveError, match="compression ratio"):
        load_python_archive(
            compressed,
            ArchiveLimits(max_compression_ratio=5.0),
        )


def test_member_bytes_are_truncated_without_execution(tmp_path):
    archive_path = tmp_path / "large.zip"
    _write_zip(archive_path, [("large.py", "#" * 100)])
    contents = load_python_archive(
        archive_path,
        ArchiveLimits(max_member_bytes=20),
    )
    assert len(contents.sources[0].payload) == 20
    assert contents.sources[0].truncated
    assert contents.warnings == ("python-members-truncated:1",)
    analysis = analyze_sources(contents.sources, enable_dataflow=False)[0]
    assert analysis.truncated


def test_tar_reads_regular_python_and_skips_link(tmp_path):
    archive_path = tmp_path / "sample.tar.gz"
    payload = b"import os\nvalue = os.getenv('MODE')\n"
    with tarfile.open(archive_path, "w:gz") as archive:
        source = tarfile.TarInfo("package/main.py")
        source.size = len(payload)
        archive.addfile(source, io.BytesIO(payload))
        link = tarfile.TarInfo("package/link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "main.py"
        archive.addfile(link)

    contents = load_python_archive(archive_path)
    analyses = analyze_sources(contents.sources, enable_dataflow=True)

    assert contents.archive_format == "tar-gzip"
    assert contents.members_seen == 2
    assert contents.warnings == ("special-members-skipped:1",)
    assert len(analyses) == 1
    assert any(event.op == "ENV_READ" for event in analyses[0].events)


def test_archive_path_symlink_and_invalid_limits_are_rejected(tmp_path):
    archive_path = tmp_path / "real.zip"
    _write_zip(archive_path, [("main.py", "x = 1")])
    link = tmp_path / "link.zip"
    link.symlink_to(archive_path)

    with pytest.raises(UnsafeArchiveError, match="symlink"):
        load_python_archive(link)
    with pytest.raises(ValueError, match="positive"):
        load_python_archive(
            archive_path,
            ArchiveLimits(max_archive_bytes=0),
        )
