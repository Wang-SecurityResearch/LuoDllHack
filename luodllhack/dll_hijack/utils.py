# -*- coding: utf-8 -*-
"""
sys_dll/utils.py
Utility functions and helper classes.
"""

import os
import math
import ctypes

from .constants import APISET_MAP


def resolve_forwarder_module(module: str) -> str:
    """Resolve API set schema or module name to actual DLL name.

    Args:
        module: Module name, possibly an API set schema name

    Returns:
        Resolved DLL name in uppercase without extension
    """
    m = module.lower().rstrip('.dll')
    if m in APISET_MAP:
        return APISET_MAP[m]
    if m.startswith('api-ms-win-') or m.startswith('ext-ms-win-'):
        return 'KERNELBASE'
    return module.rstrip('.dll').upper()


# --- Ctypes Definitions for WinTrust ---

class GUID(ctypes.Structure):
    """Windows GUID structure."""
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8)
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    """WinTrust file info structure."""
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", ctypes.c_void_p),
        ("pgKnownSubject", ctypes.POINTER(GUID))
    ]


class WINTRUST_DATA(ctypes.Structure):
    """WinTrust data structure."""
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_ulong),
        ("fdwRevocationChecks", ctypes.c_ulong),
        ("dwUnionChoice", ctypes.c_ulong),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", ctypes.c_ulong),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_ulong),
        ("dwUIContext", ctypes.c_ulong),
        ("pSignatureSettings", ctypes.c_void_p)
    ]


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)


class WinTrustVerifier:
    """Handles Windows Authenticode signature verification."""

    @staticmethod
    def verify(file_path: str) -> bool:
        """Verify Authenticode signature of a file.

        Args:
            file_path: Path to the file to verify

        Returns:
            True if signature is valid, False otherwise
        """
        if os.name != 'nt':
            return False  # Not supported on non-Windows

        try:
            wintrust = ctypes.windll.wintrust

            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = file_path
            file_info.hFile = None
            file_info.pgKnownSubject = None

            trust_data = WINTRUST_DATA()
            trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            trust_data.dwUIChoice = 2  # WTD_UI_NONE
            trust_data.fdwRevocationChecks = 0
            trust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
            trust_data.pFile = ctypes.pointer(file_info)
            trust_data.dwStateAction = 0  # WTD_STATEACTION_IGNORE
            trust_data.dwProvFlags = 0x00000010  # WTD_CACHE_ONLY_URL_RETRIEVAL

            status = wintrust.WinVerifyTrust(
                None,
                ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(trust_data)
            )
            return status == 0
        except Exception:
            return False


class SecurityUtils:
    """Security-related utility functions."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Bytes to analyze

        Returns:
            Entropy value between 0 and 8
        """
        if not data:
            return 0.0

        entropy = 0.0
        total = len(data)
        counts = {}

        for b in data:
            counts[b] = counts.get(b, 0) + 1

        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy
