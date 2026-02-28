# -*- coding: utf-8 -*-
"""
sys_dll/parser.py
PE file parser for extracting structured information.
"""

from pathlib import Path
from typing import List, Dict, Optional

from .constants import MACHINE_AMD64, MACHINE_ARM64
from .models import PEInfo, TLSCallback, VersionInfo
from .interfaces import ExportExtractor
from .extractors import CompositeExtractor
from .utils import SecurityUtils

# Optional dependency
try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False


class PEParser:
    """Unified PE file parser that produces PEInfo objects."""

    def __init__(self, extractor: ExportExtractor = None):
        """Initialize parser with optional custom extractor.

        Args:
            extractor: Export extractor to use. Defaults to CompositeExtractor.
        """
        self._extractor = extractor or CompositeExtractor()

    def parse(self, dll_path: Path) -> PEInfo:
        """Parse a PE file and return structured information.

        Args:
            dll_path: Path to the DLL file

        Returns:
            PEInfo object with parsed information

        Raises:
            FileNotFoundError: If DLL file doesn't exist
        """
        if not dll_path.exists():
            raise FileNotFoundError(f"DLL not found: {dll_path}")

        if HAVE_PEFILE:
            return self._parse_with_pefile(dll_path)
        else:
            return self._parse_minimal(dll_path)

    def _parse_with_pefile(self, dll_path: Path) -> PEInfo:
        """Parse PE using pefile library for full information."""
        pe = pefile.PE(str(dll_path))

        machine = pe.FILE_HEADER.Machine
        is_64bit = machine == MACHINE_AMD64
        is_arm64 = machine == MACHINE_ARM64

        # Extract imports
        imports = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else 'unknown'
                imports[dll_name] = [
                    imp.name.decode('utf-8', errors='ignore') if imp.name else f"ordinal_{imp.ordinal}"
                    for imp in entry.imports
                ]

        # Extract delay imports
        delay_imports = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else 'unknown'
                delay_imports[dll_name] = [
                    imp.name.decode('utf-8', errors='ignore') if imp.name else f"ordinal_{imp.ordinal}"
                    for imp in entry.imports
                ]

        # Extract sections with entropy
        sections = []
        for section in pe.sections:
            sections.append({
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'characteristics': section.Characteristics,
                'entropy': SecurityUtils.calculate_entropy(section.get_data())
            })

        # Extract TLS callbacks
        tls_callbacks = self._extract_tls_callbacks(pe)
        has_tls = len(tls_callbacks) > 0 or hasattr(pe, 'DIRECTORY_ENTRY_TLS')

        # Extract version info
        version_info = self._extract_version_info(pe)

        # Extract exports
        exports = self._extractor.extract(dll_path)

        return PEInfo(
            path=dll_path,
            machine=machine,
            image_base=pe.OPTIONAL_HEADER.ImageBase,
            entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            is_64bit=is_64bit,
            exports=exports,
            imports=imports,
            sections=sections,
            is_arm64=is_arm64,
            tls_callbacks=tls_callbacks,
            has_tls=has_tls,
            version_info=version_info,
            delay_imports=delay_imports
        )

    def _parse_minimal(self, dll_path: Path) -> PEInfo:
        """Minimal PE parsing without pefile library."""
        with open(dll_path, 'rb') as f:
            # Read DOS header
            f.seek(0x3c)
            pe_offset = int.from_bytes(f.read(4), 'little')

            # Read PE signature and file header
            f.seek(pe_offset + 4)
            machine = int.from_bytes(f.read(2), 'little')

            # Read optional header for image base
            f.seek(pe_offset + 24)
            magic = int.from_bytes(f.read(2), 'little')
            is_64bit = magic == 0x20b  # PE32+

            if is_64bit:
                f.seek(pe_offset + 24 + 24)  # ImageBase offset in PE32+
                image_base = int.from_bytes(f.read(8), 'little')
                f.seek(pe_offset + 24 + 16)
                entry_point = int.from_bytes(f.read(4), 'little')
            else:
                f.seek(pe_offset + 24 + 28)  # ImageBase offset in PE32
                image_base = int.from_bytes(f.read(4), 'little')
                f.seek(pe_offset + 24 + 16)
                entry_point = int.from_bytes(f.read(4), 'little')

        exports = self._extractor.extract(dll_path) if self._extractor.is_available() else []

        return PEInfo(
            path=dll_path,
            machine=machine,
            image_base=image_base,
            entry_point=entry_point,
            is_64bit=is_64bit,
            exports=exports
        )

    def _extract_tls_callbacks(self, pe) -> List[TLSCallback]:
        """Extract TLS callback information from PE.

        Args:
            pe: pefile.PE object

        Returns:
            List of TLSCallback objects
        """
        callbacks = []

        if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            return callbacks

        tls = pe.DIRECTORY_ENTRY_TLS.struct

        # TLS callback array is at AddressOfCallBacks
        callback_array_rva = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

        if callback_array_rva <= 0:
            return callbacks

        # Read callback addresses from the array
        try:
            ptr_size = 8 if pe.FILE_HEADER.Machine == MACHINE_AMD64 else 4
            offset = pe.get_offset_from_rva(callback_array_rva)

            idx = 0
            while True:
                data = pe.get_data(callback_array_rva + idx * ptr_size, ptr_size)
                if len(data) < ptr_size:
                    break

                if ptr_size == 8:
                    addr = int.from_bytes(data, 'little')
                else:
                    addr = int.from_bytes(data, 'little')

                if addr == 0:
                    break

                rva = addr - pe.OPTIONAL_HEADER.ImageBase
                callbacks.append(TLSCallback(rva=rva, index=idx))
                idx += 1

                # Safety limit
                if idx > 100:
                    break

        except Exception:
            pass

        return callbacks

    def _extract_version_info(self, pe) -> Optional[VersionInfo]:
        """Extract version resource information from PE.

        Args:
            pe: pefile.PE object

        Returns:
            VersionInfo object or None if not available
        """
        if not hasattr(pe, 'VS_VERSIONINFO') and not hasattr(pe, 'FileInfo'):
            # Try to parse version info
            try:
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
                )
            except Exception:
                pass

        if not hasattr(pe, 'FileInfo'):
            return None

        version_info = VersionInfo()

        try:
            for fileinfo in pe.FileInfo:
                for info in fileinfo:
                    if hasattr(info, 'StringTable'):
                        for st in info.StringTable:
                            for entry in st.entries.items():
                                key = entry[0].decode('utf-8', errors='ignore') if isinstance(entry[0], bytes) else entry[0]
                                val = entry[1].decode('utf-8', errors='ignore') if isinstance(entry[1], bytes) else entry[1]

                                if key == 'FileVersion':
                                    version_info.file_version = val
                                elif key == 'ProductVersion':
                                    version_info.product_version = val
                                elif key == 'CompanyName':
                                    version_info.company_name = val
                                elif key == 'FileDescription':
                                    version_info.file_description = val
                                elif key == 'InternalName':
                                    version_info.internal_name = val
                                elif key == 'OriginalFilename':
                                    version_info.original_filename = val
                                elif key == 'ProductName':
                                    version_info.product_name = val
                                elif key == 'LegalCopyright':
                                    version_info.legal_copyright = val

        except Exception:
            return None

        # Only return if we found at least some info
        if version_info.file_version or version_info.product_name:
            return version_info

        return None
