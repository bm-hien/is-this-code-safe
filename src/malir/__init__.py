"""ITCS core: CPU-first static behavior analysis using MalIR."""

from .extractor import PythonExtractor
from .scanner import Scanner
from .types import Event, FileAnalysis, ScanReport

__all__ = ["Event", "FileAnalysis", "PythonExtractor", "ScanReport", "Scanner"]
__version__ = "0.1.0"
