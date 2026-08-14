"""Bounded filesystem scanner for Python source trees."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, replace
from pathlib import Path

from .detector import CascadeConfig, ProbabilityModel, decide
from .extractor import ExtractorLimits, PythonExtractor
from .types import FileAnalysis, ScanReport

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
}


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_files: int = 10_000
    max_file_bytes: int = 1_000_000
    max_total_bytes: int = 100_000_000


class Scanner:
    def __init__(
        self,
        model: ProbabilityModel | None = None,
        limits: ScanLimits | None = None,
        cascade: CascadeConfig | None = None,
        *,
        enable_dataflow: bool = True,
        enable_call_summaries: bool = True,
    ) -> None:
        self.model = model
        self.limits = limits or ScanLimits()
        self.cascade = cascade or CascadeConfig()
        self.enable_dataflow = enable_dataflow
        self.enable_call_summaries = enable_dataflow and enable_call_summaries
        extractor_limits = ExtractorLimits(
            max_file_bytes=self.limits.max_file_bytes,
        )
        if not self.enable_call_summaries:
            extractor_limits = replace(
                extractor_limits,
                max_call_depth=0,
                max_call_expansions=0,
            )
        self.extractor = PythonExtractor(
            extractor_limits,
            enable_dataflow=enable_dataflow,
        )

    def scan(self, target: str | Path) -> ScanReport:
        started = time.perf_counter()
        root = Path(target).resolve()
        if not root.exists():
            raise FileNotFoundError(str(root))
        analyses: list[FileAnalysis] = []
        warnings: list[str] = []
        skipped = 0
        total_bytes = 0
        for path in self._iter_python_files(root):
            if len(analyses) >= self.limits.max_files:
                warnings.append("file limit reached")
                break
            try:
                info = path.lstat()
                if path.is_symlink() or not path.is_file():
                    skipped += 1
                    continue
                if info.st_size > self.limits.max_file_bytes:
                    skipped += 1
                    warnings.append(f"oversized file skipped: {path}")
                    continue
                if total_bytes + info.st_size > self.limits.max_total_bytes:
                    warnings.append("total byte limit reached")
                    break
                display = _display_path(root, path)
                analysis = self.extractor.analyze_file(path, display)
                analyses.append(analysis)
                if analysis.parse_error:
                    warnings.append(f"parse error in {display}: {analysis.parse_error}")
                if analysis.event_limit_reached:
                    warnings.append(f"event limit reached in {display}")
                total_bytes += info.st_size
            except (OSError, UnicodeError) as error:
                skipped += 1
                warnings.append(f"cannot read {path}: {error}")

        decision = decide(analyses, self.model, self.cascade)
        elapsed = (time.perf_counter() - started) * 1_000.0
        return ScanReport(
            target=str(root),
            verdict=decision.verdict,
            risk_score=decision.risk_score,
            rule_score=decision.rule_score,
            model_probability=decision.model_probability,
            model_used=decision.model_used,
            files_scanned=len(analyses),
            files_skipped=skipped,
            elapsed_ms=elapsed,
            evidence=decision.evidence,
            files=analyses,
            warnings=warnings,
        )

    @staticmethod
    def _iter_python_files(root: Path):
        if root.is_file():
            if root.suffix.lower() == ".py":
                yield root
            return
        for current, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(
                name for name in dirnames if name not in DEFAULT_EXCLUDED_DIRS
            )
            for name in sorted(filenames):
                if name.lower().endswith(".py"):
                    yield Path(current, name)


def _display_path(root: Path, path: Path) -> str:
    if root.is_file():
        return path.name
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)
