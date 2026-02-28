# -*- coding: utf-8 -*-
"""
luodllhack/dll_hijack/interfaces.py
Abstract interfaces for export extraction and code emission.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from luodllhack.core.signatures.models import FunctionSignature as ExportSymbol
from .models import PEInfo


class ExportExtractor(ABC):
    """Abstract interface for extracting exports from DLLs."""

    @abstractmethod
    def extract(self, dll_path: Path) -> List[ExportSymbol]:
        """Extract all exports from the given DLL."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this extractor is available on the system."""
        pass


class CodeEmitter(ABC):
    """Abstract interface for emitting proxy code."""

    @abstractmethod
    def emit(self, pe_info: PEInfo, output_dir: Path) -> List[Path]:
        """Generate proxy files and return list of created file paths."""
        pass

    @abstractmethod
    def get_file_extensions(self) -> List[str]:
        """Return list of file extensions this emitter produces."""
        pass
