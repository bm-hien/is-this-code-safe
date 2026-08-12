"""Safe fixture: this file is parsed, never imported by tests."""

from pathlib import Path


def count_nonempty_lines(path: str) -> int:
    text = Path(path).read_text(encoding="utf-8")
    return sum(bool(line.strip()) for line in text.splitlines())
