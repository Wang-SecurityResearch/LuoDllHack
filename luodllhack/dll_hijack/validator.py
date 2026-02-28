# -*- coding: utf-8 -*-
"""
luodllhack/dll_hijack/validator.py
Export validation and verification utilities.
"""

import re
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass

from luodllhack.core.signatures.models import FunctionSignature as ExportSymbol
from .models import PEInfo


@dataclass
class ValidationResult:
    """Result of export validation."""
    is_valid: bool
    original_count: int
    generated_count: int
    missing_exports: List[str]
    extra_exports: List[str]
    mismatched_ordinals: List[Tuple[str, int, int]]  # (name, expected, actual)
    warnings: List[str]

    @property
    def summary(self) -> str:
        """Generate human-readable summary."""
        if self.is_valid:
            return f"[OK] Valid: {self.generated_count}/{self.original_count} exports match"

        lines = [f"[ERR] Invalid: {self.generated_count}/{self.original_count} exports"]

        if self.missing_exports:
            lines.append(f"  Missing ({len(self.missing_exports)}): {', '.join(self.missing_exports[:5])}")
            if len(self.missing_exports) > 5:
                lines.append(f"    ... and {len(self.missing_exports) - 5} more")

        if self.extra_exports:
            lines.append(f"  Extra ({len(self.extra_exports)}): {', '.join(self.extra_exports[:5])}")

        if self.mismatched_ordinals:
            lines.append(f"  Ordinal mismatches: {len(self.mismatched_ordinals)}")

        return "\n".join(lines)


class ExportValidator:
    """Validates generated proxy exports against original DLL."""

    def validate_def_file(self, pe_info: PEInfo, def_path: Path) -> ValidationResult:
        """Validate a .def file against original PE exports.

        Args:
            pe_info: Parsed original PE information
            def_path: Path to generated .def file

        Returns:
            ValidationResult with comparison details
        """
        if not def_path.exists():
            return ValidationResult(
                is_valid=False,
                original_count=len(pe_info.exports),
                generated_count=0,
                missing_exports=[e.get_export_name() for e in pe_info.exports],
                extra_exports=[],
                mismatched_ordinals=[],
                warnings=["DEF file not found"]
            )

        # Parse DEF file exports
        def_exports = self._parse_def_file(def_path)

        return self._compare_exports(pe_info.exports, def_exports)

    def validate_c_file(self, pe_info: PEInfo, c_path: Path) -> ValidationResult:
        """Validate a C source file pragma exports against original PE.

        Args:
            pe_info: Parsed original PE information
            c_path: Path to generated C source file

        Returns:
            ValidationResult with comparison details
        """
        if not c_path.exists():
            return ValidationResult(
                is_valid=False,
                original_count=len(pe_info.exports),
                generated_count=0,
                missing_exports=[e.get_export_name() for e in pe_info.exports],
                extra_exports=[],
                mismatched_ordinals=[],
                warnings=["C file not found"]
            )

        # Parse pragma exports from C file
        pragma_exports = self._parse_pragma_exports(c_path)

        return self._compare_exports(pe_info.exports, pragma_exports)

    def _parse_def_file(self, def_path: Path) -> List[Dict]:
        """Parse exports from a .def file."""
        exports = []
        content = def_path.read_text(encoding='utf-8')

        in_exports = False
        for line in content.splitlines():
            line = line.strip()

            if line.upper() == 'EXPORTS':
                in_exports = True
                continue

            if not in_exports or not line or line.startswith(';'):
                continue

            # Parse export line: name = target @ordinal [NONAME] [DATA]
            export_info = self._parse_def_export_line(line)
            if export_info:
                exports.append(export_info)

        return exports

    def _parse_def_export_line(self, line: str) -> Optional[Dict]:
        """Parse a single DEF file export line."""
        # Pattern: name = target @ordinal NONAME DATA
        # Or: name = target @ordinal
        # Or: name @ordinal

        parts = line.split()
        if not parts:
            return None

        name = parts[0]
        ordinal = None
        is_noname = 'NONAME' in line.upper()
        is_data = 'DATA' in line.upper()

        # Find ordinal
        for part in parts:
            if part.startswith('@'):
                try:
                    ordinal = int(part[1:])
                except ValueError:
                    pass

        return {
            'name': name if not is_noname else None,
            'ordinal': ordinal,
            'is_data': is_data,
            'is_noname': is_noname
        }

    def _parse_pragma_exports(self, c_path: Path) -> List[Dict]:
        """Parse exports from C file (pragma and __declspec(dllexport))."""
        exports = []
        content = c_path.read_text(encoding='utf-8')

        # Pattern 1: #pragma comment(linker, "/EXPORT:name=target,@ordinal,NONAME,DATA")
        pragma_pattern = re.compile(
            r'#pragma\s+comment\s*\(\s*linker\s*,\s*["\']'
            r'/EXPORT:([^"\']+)["\']'
            r'\s*\)',
            re.IGNORECASE
        )

        for match in pragma_pattern.finditer(content):
            export_spec = match.group(1)
            export_info = self._parse_export_spec(export_spec)
            if export_info:
                exports.append(export_info)

        # Pattern 2: __declspec(dllexport) [return_type] [calling_conv] function_name(
        # This catches direct exports like: __declspec(dllexport) void* __cdecl AddMRUStringW(
        dllexport_pattern = re.compile(
            r'__declspec\s*\(\s*dllexport\s*\)\s+'
            r'(?:[\w*\s]+?)\s+'      # return type (void*, int, etc.)
            r'(?:__cdecl|__stdcall|__fastcall)?\s*'  # optional calling convention
            r'(\w+)\s*\(',           # function name
            re.IGNORECASE
        )

        for match in dllexport_pattern.finditer(content):
            func_name = match.group(1)
            # Skip internal functions like SetProxyHooks
            if func_name.startswith('SetProxy') or func_name.startswith('OnProxy'):
                continue
            # Skip ordinal implementation functions (they're handled by pragmas)
            if func_name.endswith('_impl'):
                continue
            # Skip _proxy_* functions (they're handled by pragmas for C++ exports)
            if func_name.startswith('_proxy_'):
                continue
            export_info = {
                'name': func_name,
                'ordinal': None,
                'is_noname': False,
                'is_data': False,
                'is_named': True
            }
            exports.append(export_info)

        return exports

    def _parse_export_spec(self, spec: str) -> Optional[Dict]:
        """Parse export specification: name=target,@ordinal,NONAME,DATA"""
        parts = spec.split(',')
        if not parts:
            return None

        # First part is name=target or just name
        first = parts[0]
        if '=' in first:
            name = first.split('=')[0]
        else:
            name = first

        ordinal = None
        is_noname = False
        is_data = False

        for part in parts[1:]:
            part = part.strip().upper()
            if part.startswith('@'):
                try:
                    ordinal = int(part[1:])
                except ValueError:
                    pass
            elif part == 'NONAME':
                is_noname = True
            elif part == 'DATA':
                is_data = True

        return {
            'name': name if not is_noname else None,
            'ordinal': ordinal,
            'is_data': is_data,
            'is_noname': is_noname
        }

    def _compare_exports(
        self,
        original: List[ExportSymbol],
        generated: List[Dict]
    ) -> ValidationResult:
        """Compare original exports with generated exports."""

        # Build lookup sets
        orig_names: Set[str] = set()
        orig_ordinals: Dict[int, str] = {}

        for exp in original:
            if exp.is_named:
                orig_names.add(exp.name)
            orig_ordinals[exp.ordinal] = exp.name or f"@{exp.ordinal}"

        gen_names: Set[str] = set()
        gen_ordinals: Dict[int, str] = {}

        for exp in generated:
            if exp.get('name'):
                gen_names.add(exp['name'])
            if exp.get('ordinal'):
                gen_ordinals[exp['ordinal']] = exp.get('name') or f"@{exp['ordinal']}"

        # Find discrepancies
        missing_exports = []
        for exp in original:
            if exp.is_named and exp.name not in gen_names:
                # Check if it's exported by ordinal
                if exp.ordinal not in gen_ordinals:
                    missing_exports.append(exp.get_export_name())

        extra_exports = list(gen_names - orig_names)

        # Check ordinal mismatches
        mismatched_ordinals = []
        for exp in original:
            if exp.ordinal in gen_ordinals:
                gen_name = gen_ordinals[exp.ordinal]
                orig_name = exp.name or f"@{exp.ordinal}"
                # Allow placeholder names for ordinal-only exports
                if not (gen_name.startswith('__exp_ord_') or gen_name.startswith('__ordinal_')):
                    if gen_name != orig_name:
                        mismatched_ordinals.append((orig_name, exp.ordinal, -1))

        # Generate warnings
        warnings = []
        data_count = sum(1 for e in original if e.is_data)
        if data_count > 0:
            warnings.append(f"Contains {data_count} DATA exports (verify DATA flag is set)")

        cpp_count = sum(1 for e in original if e.is_cpp_mangled)
        if cpp_count > 0:
            warnings.append(f"Contains {cpp_count} C++ decorated names")

        is_valid = len(missing_exports) == 0 and len(mismatched_ordinals) == 0

        return ValidationResult(
            is_valid=is_valid,
            original_count=len(original),
            generated_count=len(generated),
            missing_exports=missing_exports,
            extra_exports=extra_exports,
            mismatched_ordinals=mismatched_ordinals,
            warnings=warnings
        )


def validate_proxy(pe_info: PEInfo, output_dir: Path) -> Dict[str, ValidationResult]:
    """Validate all generated proxy files.

    Args:
        pe_info: Parsed original PE information
        output_dir: Directory containing generated files

    Returns:
        Dictionary mapping filename to ValidationResult
    """
    validator = ExportValidator()
    results = {}

    dll_name = pe_info.path.stem.lower()

    # Check DEF file
    def_path = output_dir / f"proxy_{dll_name}.def"
    if def_path.exists():
        results[def_path.name] = validator.validate_def_file(pe_info, def_path)

    # Check C file (static proxy)
    c_path = output_dir / f"proxy_{dll_name}.c"
    if c_path.exists():
        results[c_path.name] = validator.validate_c_file(pe_info, c_path)

    # Check dynamic proxy - use DEF file for validation (exports are defined there, not in C)
    dynamic_def_path = output_dir / f"proxy_{dll_name}_dynamic.def"
    if dynamic_def_path.exists():
        results[dynamic_def_path.name] = validator.validate_def_file(pe_info, dynamic_def_path)
    else:
        # Fallback to C file if DEF doesn't exist (legacy mode)
        dynamic_c_path = output_dir / f"proxy_{dll_name}_dynamic.c"
        if dynamic_c_path.exists():
            results[dynamic_c_path.name] = validator.validate_c_file(pe_info, dynamic_c_path)

    return results
