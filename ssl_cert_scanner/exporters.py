"""
exporters.py
Exports results to JSON or CSV: the format you need to feed a SIEM, a
CMDB, or any Certificate Lifecycle Management platform that can
import tabular files.
"""

import csv
import json
from pathlib import Path


def export_json(results: list[dict], path: str) -> None:
    Path(path).write_text(json.dumps(results, indent=2, ensure_ascii=False))


def export_csv(results: list[dict], path: str) -> None:
    if not results:
        Path(path).write_text("")
        return

    fieldnames = list(results[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            row = dict(row)
            if isinstance(row.get("san"), list):
                row["san"] = ";".join(row["san"])
            if isinstance(row.get("flags"), list):
                row["flags"] = ";".join(row["flags"])
            writer.writerow(row)
