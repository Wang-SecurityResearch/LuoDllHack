# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/sanitizer.py

Sanitizer Recognition - Phase 1.2

Core Capabilities:
    1. Identify data sanitization/validation functions
    2. Track whether tainted data has been sanitized
    3. Determine whether sanitization effectively eliminates vulnerability risks

Sanitization Types:
    - Length Limit: strncpy, snprintf, StringCchCopy
    - Encoding/Escaping: HtmlEncode, UrlEncode, EscapeString
    - Path Canonicalization: PathCanonicalize, GetFullPathName
    - Input Validation: isalnum, isdigit, regex matching
    - Null Pointer Check: Explicit NULL checks

Principle:
    If tainted data is processed by an appropriate sanitization function before reaching a sink,
    the risk of certain types of vulnerabilities may have been eliminated.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Any, Union
from enum import Enum, auto


class SanitizeType(Enum):
    """Sanitization Type"""
    LENGTH_LIMIT = auto()      # Length limit
    ENCODING = auto()          # Encoding/Escaping
    PATH_NORMALIZE = auto()    # Path normalization
    INPUT_VALIDATION = auto()  # Input validation
    NULL_CHECK = auto()        # Null pointer check
    TYPE_CAST = auto()         # Type casting
    BOUNDS_CHECK = auto()      # Bounds check
    WHITELIST = auto()         # Whitelist filtering


class VulnCategory(Enum):
    """Vulnerability Category (Mitigatable by sanitization)"""
    BUFFER_OVERFLOW = auto()
    FORMAT_STRING = auto()
    COMMAND_INJECTION = auto()
    PATH_TRAVERSAL = auto()
    SQL_INJECTION = auto()
    XSS = auto()
    NULL_DEREF = auto()
    INTEGER_OVERFLOW = auto()


@dataclass
class SanitizeEvent:
    """Sanitization Event"""
    addr: int
    api_name: str
    sanitize_type: SanitizeType
    mitigates: List[VulnCategory]
    # Sanitized parameter positions
    sanitized_args: List[int]
    # Whether sanitization is completely effective
    is_complete: bool = True
    # Notes
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            'addr': f'0x{self.addr:x}',
            'api': self.api_name,
            'type': self.sanitize_type.name,
            'mitigates': [v.name for v in self.mitigates],
            'is_complete': self.is_complete,
            'notes': self.notes
        }


@dataclass
class SanitizeCheckResult:
    """Sanitization Check Result"""
    is_sanitized: bool
    sanitizer_name: str = ""
    sanitize_type: Optional[SanitizeType] = None
    mitigated_vulns: List[VulnCategory] = field(default_factory=list)
    sanitize_events: List[SanitizeEvent] = field(default_factory=list)
    # Whether sanitization is complete
    is_complete_sanitization: bool = False
    notes: List[str] = field(default_factory=list)


class SanitizerDetector:
    """
    Sanitizer Recognizer

    Usage:
        detector = SanitizerDetector()

        # Check if API call is a sanitization function
        event = detector.check_api_call(b'strncpy', addr, [0, 1, 2])
        if event:
            print(f"Sanitizer: {event.api_name}")

        # Check if data has been sanitized
        result = detector.check_sanitized('rcx', call_trace)
        if result.is_sanitized:
            print(f"Data sanitized: {result.sanitizer_name}")
    """

    # ==========================================================================
    # Sanitizer Database
    # ==========================================================================

    # Length limit functions
    LENGTH_SANITIZERS: Dict[bytes, Dict[str, Any]] = {
        # C Standard Library
        b'strncpy': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],  # Destination buffer
            'size_arg': 2,
            'notes': 'Limits copy length but does not guarantee null termination'
        },
        b'strncat': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 2,
        },
        b'snprintf': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW, VulnCategory.FORMAT_STRING],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
            'notes': 'Fully safe, limits length and guarantees null termination'
        },
        b'vsnprintf': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW, VulnCategory.FORMAT_STRING],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'fgets': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'_snprintf': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
        },
        b'_snwprintf': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
        },

        # Windows Secure String Functions (StringCch*)
        b'StringCchCopyA': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
            'notes': 'Windows secure string function, fully safe'
        },
        b'StringCchCopyW': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'StringCchCatA': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'StringCchCatW': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'StringCchPrintfA': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW, VulnCategory.FORMAT_STRING],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'StringCchPrintfW': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW, VulnCategory.FORMAT_STRING],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },

        # Windows Secure String Functions (StringCbCopy*)
        b'StringCbCopyA': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'StringCbCopyW': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },

        # memcpy_s etc. safe versions
        b'memcpy_s': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'memmove_s': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'strcpy_s': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'strcat_s': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'wcscpy_s': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
        b'wcscat_s': {
            'type': SanitizeType.LENGTH_LIMIT,
            'mitigates': [VulnCategory.BUFFER_OVERFLOW],
            'sanitized_args': [0],
            'size_arg': 1,
            'is_complete': True,
        },
    }

    # Path normalization functions
    PATH_SANITIZERS: Dict[bytes, Dict[str, Any]] = {
        b'PathCanonicalizeA': {
            'type': SanitizeType.PATH_NORMALIZE,
            'mitigates': [VulnCategory.PATH_TRAVERSAL],
            'sanitized_args': [0, 1],
            'is_complete': True,
            'notes': 'Canonicalizes path, eliminating ../ traverses'
        },
        b'PathCanonicalizeW': {
            'type': SanitizeType.PATH_NORMALIZE,
            'mitigates': [VulnCategory.PATH_TRAVERSAL],
            'sanitized_args': [0, 1],
            'is_complete': True,
        },
        b'GetFullPathNameA': {
            'type': SanitizeType.PATH_NORMALIZE,
            'mitigates': [VulnCategory.PATH_TRAVERSAL],
            'sanitized_args': [0],
            'is_complete': False,  # Incomplete, may require extra checks
            'notes': 'Converts to absolute path, but still requires directory boundary verification'
        },
        b'GetFullPathNameW': {
            'type': SanitizeType.PATH_NORMALIZE,
            'mitigates': [VulnCategory.PATH_TRAVERSAL],
            'sanitized_args': [0],
            'is_complete': False,
        },
        b'PathIsRelativeA': {
            'type': SanitizeType.INPUT_VALIDATION,
            'mitigates': [VulnCategory.PATH_TRAVERSAL],
            'sanitized_args': [0],
            'is_complete': False,
            'notes': 'Checks if path is relative, used for validation'
        },
        b'PathIsRelativeW': {
            'type': SanitizeType.INPUT_VALIDATION,
            'mitigates': [VulnCategory.PATH_TRAVERSAL],
            'sanitized_args': [0],
            'is_complete': False,
        },
    }

    # Encoding/Escaping functions
    ENCODING_SANITIZERS: Dict[bytes, Dict[str, Any]] = {
        # URL Encoding
        b'UrlEscapeA': {
            'type': SanitizeType.ENCODING,
            'mitigates': [VulnCategory.COMMAND_INJECTION, VulnCategory.XSS],
            'sanitized_args': [0],
            'is_complete': True,
        },
        b'UrlEscapeW': {
            'type': SanitizeType.ENCODING,
            'mitigates': [VulnCategory.COMMAND_INJECTION, VulnCategory.XSS],
            'sanitized_args': [0],
            'is_complete': True,
        },
        # Shell Escaping
        b'CommandLineToArgvA': {
            'type': SanitizeType.ENCODING,
            'mitigates': [VulnCategory.COMMAND_INJECTION],
            'sanitized_args': [0],
            'is_complete': False,
        },
        b'CommandLineToArgvW': {
            'type': SanitizeType.ENCODING,
            'mitigates': [VulnCategory.COMMAND_INJECTION],
            'sanitized_args': [0],
            'is_complete': False,
        },
    }

    # Input validation functions
    VALIDATION_SANITIZERS: Dict[bytes, Dict[str, Any]] = {
        b'isalnum': {
            'type': SanitizeType.INPUT_VALIDATION,
            'mitigates': [VulnCategory.COMMAND_INJECTION, VulnCategory.SQL_INJECTION],
            'sanitized_args': [0],
            'is_complete': False,
            'notes': 'Single character validation, requires loop'
        },
        b'isalpha': {
            'type': SanitizeType.INPUT_VALIDATION,
            'mitigates': [VulnCategory.COMMAND_INJECTION, VulnCategory.SQL_INJECTION],
            'sanitized_args': [0],
            'is_complete': False,
        },
        b'isdigit': {
            'type': SanitizeType.INPUT_VALIDATION,
            'mitigates': [VulnCategory.COMMAND_INJECTION, VulnCategory.SQL_INJECTION, VulnCategory.INTEGER_OVERFLOW],
            'sanitized_args': [0],
            'is_complete': False,
        },
        b'iswdigit': {
            'type': SanitizeType.INPUT_VALIDATION,
            'mitigates': [VulnCategory.COMMAND_INJECTION, VulnCategory.SQL_INJECTION],
            'sanitized_args': [0],
            'is_complete': False,
        },
    }

    def __init__(self):
        """Initialize the sanitizer recognizer"""
        # Merge all sanitizers
        self.all_sanitizers: Dict[bytes, Dict[str, Any]] = {}
        self.all_sanitizers.update(self.LENGTH_SANITIZERS)
        self.all_sanitizers.update(self.PATH_SANITIZERS)
        self.all_sanitizers.update(self.ENCODING_SANITIZERS)
        self.all_sanitizers.update(self.VALIDATION_SANITIZERS)

        # Tracked sanitization history
        self.sanitize_history: List[SanitizeEvent] = []

    def check_api_call(self, api_name: Union[bytes, str], addr: int,
                       tainted_args: List[int] = None) -> Optional[SanitizeEvent]:
        """
        Check if API call is a sanitization function

        Args:
            api_name: API name
            addr: Call address
            tainted_args: Tainted parameter positions

        Returns:
            SanitizeEvent if sanitizer, else None
        """
        if isinstance(api_name, str):
            api_name = api_name.encode()

        if api_name not in self.all_sanitizers:
            return None

        info = self.all_sanitizers[api_name]

        event = SanitizeEvent(
            addr=addr,
            api_name=api_name.decode(),
            sanitize_type=info['type'],
            mitigates=info['mitigates'],
            sanitized_args=info['sanitized_args'],
            is_complete=info.get('is_complete', False),
            notes=info.get('notes', '')
        )

        # Record history
        self.sanitize_history.append(event)

        return event

    def check_sanitized(self, tainted_reg: str,
                        call_trace: List[Dict]) -> SanitizeCheckResult:
        """
        Check if data has been sanitized

        Args:
            tainted_reg: Tainted register
            call_trace: Call trace [{api, addr, args}, ...]

        Returns:
            SanitizeCheckResult
        """
        result = SanitizeCheckResult(is_sanitized=False)

        for call in call_trace:
            api_name = call.get('api', b'')
            addr = call.get('addr', 0)
            args = call.get('args', [])

            event = self.check_api_call(api_name, addr, args)
            if event:
                result.is_sanitized = True
                result.sanitizer_name = event.api_name
                result.sanitize_type = event.sanitize_type
                result.mitigated_vulns.extend(event.mitigates)
                result.sanitize_events.append(event)

                if event.is_complete:
                    result.is_complete_sanitization = True
                    result.notes.append(f"Complete sanitization: {event.api_name}")
                else:
                    result.notes.append(f"Partial sanitization: {event.api_name} ({event.notes})")

        return result

    def get_vuln_mitigations(self, vuln_type: str) -> List[str]:
        """
        Retrieve list of sanitization functions that can mitigate a specific vulnerability type

        Args:
            vuln_type: Name of the vulnerability type

        Returns:
            List of sanitizer function names
        """
        try:
            vuln_cat = VulnCategory[vuln_type.upper()]
        except KeyError:
            return []

        mitigators = []
        for api_name, info in self.all_sanitizers.items():
            if vuln_cat in info['mitigates']:
                mitigators.append(api_name.decode())

        return mitigators

    def is_safe_alternative(self, dangerous_api: bytes) -> Optional[bytes]:
        """
        Retrieve safe alternative for a dangerous API

        Args:
            dangerous_api: Dangerous API name

        Returns:
            Safe alternative API name, if it exists
        """
        alternatives = {
            b'strcpy': b'strcpy_s',
            b'strcat': b'strcat_s',
            b'sprintf': b'snprintf',
            b'vsprintf': b'vsnprintf',
            b'gets': b'fgets',
            b'memcpy': b'memcpy_s',
            b'memmove': b'memmove_s',
            b'lstrcpyA': b'StringCchCopyA',
            b'lstrcpyW': b'StringCchCopyW',
            b'lstrcatA': b'StringCchCatA',
            b'lstrcatW': b'StringCchCatW',
            b'wcscpy': b'wcscpy_s',
            b'wcscat': b'wcscat_s',
        }
        return alternatives.get(dangerous_api)

    def clear_history(self):
        """Clear sanitization history"""
        self.sanitize_history.clear()
