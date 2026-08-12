from pathlib import Path

import pytest

from scripts.acquire_pypi_reference import (
    MAX_ARTIFACT_BYTES,
    Artifact,
    _artifact_preference,
    _osv_identifiers,
    _prepare_output,
    _select_artifact,
    _storage_name,
    _valid_file_metadata,
)


def _release(
    filename: str,
    packagetype: str,
    *,
    marker: str = "a",
    size: int = 10,
    yanked: bool = False,
    host: str = "files.pythonhosted.org",
):
    return {
        "filename": filename,
        "packagetype": packagetype,
        "size": size,
        "url": f"https://{host}/packages/{filename}",
        "digests": {"sha256": marker * 64},
        "yanked": yanked,
        "upload_time_iso_8601": "2026-08-01T00:00:00Z",
    }


def test_select_artifact_uses_frozen_preference_order():
    payload = {
        "info": {"name": "Demo_Pkg", "version": "1.2.3"},
        "urls": [
            _release("demo-1.2.3-py3-none-any.whl", "bdist_wheel", marker="b"),
            _release("demo-1.2.3.zip", "sdist", marker="c"),
            _release("demo-1.2.3.tar.gz", "sdist", marker="d"),
            _release(
                "demo-yanked.tar.gz",
                "sdist",
                marker="e",
                yanked=True,
            ),
        ],
    }

    artifact, reason = _select_artifact(payload, 17, "demo-pkg")

    assert reason == ""
    assert artifact is not None
    assert artifact.filename == "demo-1.2.3.tar.gz"
    assert artifact.normalized_project == "demo-pkg"
    assert artifact.rank == 17


def test_select_artifact_rejects_unsafe_or_oversized_files():
    payload = {
        "info": {"name": "demo", "version": "1"},
        "urls": [
            _release("bad.tar.gz", "sdist", host="example.test"),
            _release(
                "huge.tar.gz",
                "sdist",
                size=MAX_ARTIFACT_BYTES + 1,
            ),
        ],
    }

    artifact, reason = _select_artifact(payload, 1, "demo")

    assert artifact is None
    assert reason == "no-supported-non-yanked-artifact"
    assert not _valid_file_metadata(
        "bad.tar.gz",
        "https://user@files.pythonhosted.org/bad.tar.gz",
        "a" * 64,
        10,
    )


def test_artifact_preferences_are_explicit():
    assert _artifact_preference("x.tar.gz", "sdist") == 0
    assert _artifact_preference("x.zip", "sdist") == 1
    assert _artifact_preference("x-py3-none-any.whl", "bdist_wheel") == 2
    assert _artifact_preference("x-cp312-manylinux.whl", "bdist_wheel") == 3
    assert _artifact_preference("x.exe", "bdist_wheel") is None


def test_storage_name_contains_only_rank_hash_and_supported_suffix():
    artifact = Artifact(
        rank=9,
        project="demo",
        normalized_project="demo",
        version="1",
        filename="untrusted-name.tar.gz",
        url="https://files.pythonhosted.org/packages/untrusted-name.tar.gz",
        sha256="f" * 64,
        size=10,
        packagetype="sdist",
        upload_time=None,
    )

    assert _storage_name(artifact) == f"00009-{'f' * 20}.tar.gz"


def test_osv_malicious_alias_is_detected():
    identifiers = _osv_identifiers(
        {
            "vulns": [
                {"id": "GHSA-1234", "aliases": ["MAL-2026-42"]},
                {"id": "CVE-2026-1"},
            ]
        }
    )
    assert "MAL-2026-42" in identifiers


def test_prepare_output_rejects_symlink(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        _prepare_output(link)


def test_prepare_output_rejects_unexpected_entries(tmp_path: Path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "surprise.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected acquisition output"):
        _prepare_output(output)