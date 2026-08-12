import json

import pytest

from malir.manifest import audit_manifest, hash_representation, load_manifest


def _row(sample_id, *, split="train", seen="2025-01-01", label=0, number=1):
    return {
        "sample_id": sample_id,
        "label": label,
        "ecosystem": "pypi",
        "package": f"package-{sample_id}",
        "version": "1.0.0",
        "sha256": f"{number:064x}",
        "first_seen": seen,
        "group_id": f"group-{sample_id}",
        "provenance": "synthetic-test",
        "license": "MIT",
        "content_kind": "source",
        "split": split,
        "representation_hash": f"{number + 100:064x}",
    }


def _load(tmp_path, rows):
    path = tmp_path / "manifest.jsonl"
    path.write_text(
        "\n".join(json.dumps(row) for row in rows),
        encoding="utf-8",
    )
    return load_manifest(path)


def test_representation_hash_preserves_token_boundaries():
    assert hash_representation(["a", "bc"]) != hash_representation(["ab", "c"])
    assert hash_representation(["a", "bc"]) == hash_representation(["a", "bc"])


def test_clean_manifest_is_reproducible(tmp_path):
    records = [
        _row("train", split="train", seen="2025-01-01", number=1),
        _row("validation", split="validation", seen="2025-02-01", number=2),
        _row("test", split="test", seen="2025-03-01", number=3),
    ]
    rows = _load(tmp_path, records)
    report = audit_manifest(rows)
    reversed_report = audit_manifest(list(reversed(rows)))
    assert report["valid"]
    assert report["issues"] == []
    assert report["manifest_fingerprint"] == reversed_report["manifest_fingerprint"]


def test_conflicting_label_for_same_digest_is_error(tmp_path):
    first = _row("one", label=0, number=1)
    second = _row("two", label=1, number=2)
    second["sha256"] = first["sha256"]
    report = audit_manifest(_load(tmp_path, [first, second]))
    codes = {issue["code"] for issue in report["issues"]}
    assert "conflicting-label-duplicate" in codes
    assert not report["valid"]


def test_truncated_findings_still_fail_audit(tmp_path):
    first = _row("one", number=1)
    second = _row("one", number=2)
    report = audit_manifest(_load(tmp_path, [first, second]), max_issues=0)
    assert report["issues"] == []
    assert report["issues_truncated"] > 0
    assert report["errors"] > 0
    assert not report["valid"]


def test_package_identity_closes_splits_even_with_different_groups(tmp_path):
    first = _row("one", split="train", number=1)
    second = _row("two", split="test", seen="2025-03-01", number=2)
    first["package"] = "Example_Package"
    second["package"] = "example-package"
    report = audit_manifest(_load(tmp_path, [first, second]))
    codes = {issue["code"] for issue in report["issues"]}
    assert "package-split-leakage" in codes
    assert "package-group-fragmentation" in codes


def test_group_and_representation_cannot_cross_splits(tmp_path):
    first = _row("one", split="train", number=1)
    second = _row("two", split="test", seen="2025-03-01", number=2)
    second["group_id"] = first["group_id"]
    second["representation_hash"] = first["representation_hash"]
    report = audit_manifest(_load(tmp_path, [first, second]))
    codes = {issue["code"] for issue in report["issues"]}
    assert "group-split-leakage" in codes
    assert "representation-split-leakage" in codes


def test_non_forward_time_split_is_visible_warning(tmp_path):
    train = _row("train", split="train", seen="2025-04-01", number=1)
    test = _row("test", split="test", seen="2025-03-01", number=2)
    report = audit_manifest(_load(tmp_path, [train, test]))
    assert any(issue["code"] == "non-forward-time-split" for issue in report["issues"])


@pytest.mark.parametrize("field", ["source", "tokens", "path", "archive_path"])
def test_manifest_rejects_payload_or_sample_reference(tmp_path, field):
    record = _row("one")
    record[field] = "do not read this"
    with pytest.raises(ValueError, match="metadata-only"):
        _load(tmp_path, [record])


def test_manifest_rejects_unknown_fields(tmp_path):
    record = _row("one")
    record["unknown_field"] = "must-not-enter-a-manifest"
    with pytest.raises(ValueError, match="unsupported manifest fields"):
        _load(tmp_path, [record])


def test_manifest_rejects_symlink(tmp_path):
    real = tmp_path / "real.jsonl"
    real.write_text(json.dumps(_row("one")), encoding="utf-8")
    link = tmp_path / "manifest.jsonl"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        load_manifest(link)


def test_manifest_rejects_noncanonical_hash(tmp_path):
    record = _row("one")
    record["sha256"] = "A" * 64
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        _load(tmp_path, [record])
