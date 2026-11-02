import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from scripts.eval.manifest import (
    FIELDS,
    MANIFEST_CSV,
    SCHEMA_JSON,
    ManifestRow,
    read_manifest,
    schema_text,
    write_manifest,
)

SHA = "a" * 64


def _rows() -> list[ManifestRow]:
    return [
        ManifestRow(
            name="evil",
            version="1.0",
            artifact_filename="samples/pypi/x/evil/1.0/e.zip",
            sha256=SHA,
            label="malicious",
            source="datadog",
            campaign_group="payload-abc",
            split="train",
            fold=3,
            normalized_source_sha256="b" * 64,
            notes="datadog:malicious_intent; has, comma",
        ),
        ManifestRow(
            name="requests",
            label="benign",
            source="top-pypi",
            popularity_band="top-100",
            split="holdout",
            manual_review="unreviewed",
        ),
    ]


def test_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "m.csv"
    write_manifest(_rows(), path)
    assert read_manifest(path) == _rows()


def test_committed_manifest_is_valid_and_header_matches() -> None:
    read_manifest(MANIFEST_CSV)
    assert MANIFEST_CSV.read_text(encoding="utf-8").splitlines()[0] == ",".join(FIELDS)


def test_committed_schema_matches_model() -> None:
    assert SCHEMA_JSON.read_text(encoding="utf-8") == schema_text()
    assert set(json.loads(schema_text())["properties"]) == set(FIELDS)


def test_header_mismatch_rejected(tmp_path: Path) -> None:
    path = tmp_path / "m.csv"
    path.write_text("name,label\n", encoding="utf-8")
    with pytest.raises(ValueError, match="header"):
        read_manifest(path)


@pytest.mark.parametrize(
    "bad",
    [
        {"label": "maybe"},
        {"source": "pypi"},
        {"split": "train"},  # train without a fold
        {"split": "holdout", "fold": 1},
        {"split": "train", "fold": 5},
        {"sha256": "XYZ"},
        {"manual_review": "fine"},
    ],
)
def test_invalid_rows_rejected(bad: dict) -> None:
    base = {"name": "x", "label": "benign", "source": "top-pypi"}
    with pytest.raises(ValidationError):
        ManifestRow.model_validate(base | bad)
