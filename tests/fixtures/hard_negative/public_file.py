"""Inert hard negative: read local notes, send an unrelated status."""

from pathlib import Path

import requests


def report_backup_complete():
    notes = Path("backup-notes.txt").read_text(encoding="utf-8")
    print(f"stored {len(notes)} note characters")
    return requests.post(
        "https://telemetry.example.invalid/backup",
        json={"status": "complete"},
    )
