"""The corpus manifest: one row per artifact, committed as ``data/manifest.csv``.

python -m scripts.eval.manifest --write-schema   # regenerate data/manifest.schema.json
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

DATA = Path(__file__).resolve().parents[2] / "data"
MANIFEST_CSV = DATA / "manifest.csv"
SCHEMA_JSON = DATA / "manifest.schema.json"

_SHA = r"^([0-9a-f]{64})?$"  # empty until the artifact has been downloaded


class ManifestRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    version: str = ""  # empty for a benign row whose latest version is not resolved yet
    # Datadog: path relative to the dataset checkout; fetched: file name in the artifacts dir.
    artifact_filename: str = ""
    sha256: str = Field(default="", pattern=_SHA)
    label: Literal["malicious", "benign"]
    source: Literal["datadog", "openssf", "top-pypi", "random-pypi"]
    campaign_group: str = ""
    popularity_band: Literal["top-100", "101-1000", "1001-5000", "random", "n/a"] = "n/a"
    split: Literal["train", "holdout", "excluded"] = "excluded"
    fold: int | None = Field(default=None, ge=0, le=4)
    normalized_source_sha256: str = Field(default="", pattern=_SHA)
    # None = not in the manual-review sample; "unreviewed" = selected, not yet looked at.
    manual_review: Literal["unreviewed", "ok", "suspicious"] | None = None
    notes: str = ""

    @model_validator(mode="after")
    def _fold_only_in_train(self) -> ManifestRow:
        if (self.split == "train") != (self.fold is not None):
            raise ValueError("fold is set exactly when split == 'train'")
        return self


FIELDS: list[str] = list(ManifestRow.model_fields)


def read_manifest(path: Path = MANIFEST_CSV) -> list[ManifestRow]:
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != FIELDS:
            raise ValueError(f"{path}: header {reader.fieldnames} != {FIELDS}")
        return [
            ManifestRow.model_validate(
                {
                    k: (None if v == "" and k in ("fold", "manual_review") else v)
                    for k, v in r.items()
                }
            )
            for r in reader
        ]


def write_manifest(rows: list[ManifestRow], path: Path = MANIFEST_CSV) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: "" if v is None else v for k, v in r.model_dump().items()})


def schema_text() -> str:
    return json.dumps(ManifestRow.model_json_schema(), indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--write-schema", action="store_true", help="regenerate the JSON schema")
    p.add_argument("--manifest", type=Path, default=MANIFEST_CSV, help="validate this manifest")
    args = p.parse_args(argv)
    if args.write_schema:
        SCHEMA_JSON.write_text(schema_text(), encoding="utf-8")
    print(f"{len(read_manifest(args.manifest))} valid rows in {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
