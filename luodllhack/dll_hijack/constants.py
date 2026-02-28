# -*- coding: utf-8 -*-
"""
sys_dll/constants.py
PE constants, security rules, and configuration values.
"""

# --- PE Machine Types ---
MACHINE_I386 = 0x014c   # x86 32-bit
MACHINE_AMD64 = 0x8664  # x64 64-bit
MACHINE_ARM64 = 0xaa64  # ARM64

# --- PE DllCharacteristics flags ---
DLL_CHAR_HIGH_ENTROPY_VA = 0x0020
DLL_CHAR_DYNAMIC_BASE = 0x0040     # ASLR
DLL_CHAR_FORCE_INTEGRITY = 0x0080
DLL_CHAR_NX_COMPAT = 0x0100        # DEP
DLL_CHAR_NO_SEH = 0x0400
DLL_CHAR_GUARD_CF = 0x4000         # CFG

# --- PE Section Characteristics ---
SECTION_MEM_EXECUTE = 0x20000000
SECTION_MEM_READ = 0x40000000
SECTION_MEM_WRITE = 0x80000000

# --- Capstone X86 Register IDs ---
X86_REG_RIP = 41

# --- DLL Reason codes for DllMain ---
DLL_PROCESS_DETACH = 0
DLL_PROCESS_ATTACH = 1
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3

# --- LoadLibraryEx flags ---
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
LOAD_LIBRARY_AS_DATAFILE = 0x00000002

# --- API Set Schema mapping ---
APISET_MAP = {
    'api-ms-win-core-version-l1-1-0': 'KERNEL32',
    'api-ms-win-core-libraryloader-l1-1-0': 'KERNEL32',
    'api-ms-win-core-processthread-l1-1-0': 'KERNEL32',
    'api-ms-win-core-heap-l1-1-0': 'KERNEL32',
    'api-ms-win-core-synch-l1-1-0': 'KERNEL32',
    'api-ms-win-core-file-l1-2-0': 'KERNEL32',
    'api-ms-win-core-errorhandling-l1-1-0': 'KERNEL32',
    'api-ms-win-core-string-l1-1-0': 'KERNEL32',
    'api-ms-win-core-registry-l1-1-0': 'ADVAPI32',
    'ext-ms-win-advapi32-registry-l1-1-0': 'ADVAPI32'
}

# --- YARA Rules for malware detection ---
YARA_RULES = """
rule Suspicious_Packer {
    meta:
        description = "Detects common packers like UPX or high entropy sections"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $aspack = ".aspack"
        $fsg = "FSG!"
    condition:
        any of them
}

rule Suspicious_Strings {
    meta:
        description = "Detects suspicious strings often used in malware"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell.exe" nocase
        $s3 = "URLDownloadToFile" nocase
        $s4 = "VirtualAlloc"
        $s5 = "WriteProcessMemory"
    condition:
        2 of them
}

rule Anti_Debug {
    meta:
        description = "Detects basic anti-debugging techniques"
    strings:
        $s1 = "IsDebuggerPresent"
        $s2 = "OutputDebugString"
        $s3 = "CheckRemoteDebuggerPresent"
    condition:
        any of them
}
"""

# --- SDL Banned APIs ---
BANNED_APIS = {
    # String operations (buffer overflow risk)
    b"strcpy": "Buffer Overflow (No bounds check)",
    b"strcpyA": "Buffer Overflow (No bounds check)",
    b"strcpyW": "Buffer Overflow (No bounds check)",
    b"wcscpy": "Buffer Overflow (No bounds check)",
    b"strcat": "Buffer Overflow (No bounds check)",
    b"strcatA": "Buffer Overflow (No bounds check)",
    b"strcatW": "Buffer Overflow (No bounds check)",
    b"wcscat": "Buffer Overflow (No bounds check)",
    b"sprintf": "Buffer Overflow (No bounds check)",
    b"wsprintf": "Buffer Overflow (No bounds check)",
    b"vsprintf": "Buffer Overflow (No bounds check)",
    b"gets": "Buffer Overflow (Always unsafe)",
    b"lstrcpyA": "Buffer Overflow (No bounds check)",
    b"lstrcpyW": "Buffer Overflow (No bounds check)",
    b"lstrcatA": "Buffer Overflow (No bounds check)",
    b"lstrcatW": "Buffer Overflow (No bounds check)",
    b"strncpy": "Buffer Overflow (Potential misuse)",
    b"wcsncpy": "Buffer Overflow (Potential misuse)",
    # Memory operations
    b"memcpy": "Memory Corruption (Check for bounds)",
    b"RtlCopyMemory": "Memory Corruption (Check for bounds)",
    b"alloca": "Stack Overflow (Dynamic stack allocation)",
    # Command execution
    b"system": "Command Injection",
    b"WinExec": "Command Injection",
    b"ShellExecuteA": "Command Injection",
    b"ShellExecuteW": "Command Injection",
    # Other
    b"IsBadReadPtr": "Memory Management (Deprecated/Unsafe)",
    b"IsBadWritePtr": "Memory Management (Deprecated/Unsafe)"
}

# --- Heuristic behavior patterns ---
HEURISTIC_BEHAVIORS = {
    "网络通信": {"socket", "connect", "send", "recv", "InternetOpen", "HttpSendRequest", "URLDownload"},
    "进程注入/操作": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetThreadContext", "OpenProcess"},
    "文件操作": {"CreateFile", "WriteFile", "ReadFile", "DeleteFile"},
    "注册表操作": {"RegOpenKey", "RegSetValue", "RegCreateKey"},
    "加解密/压缩": {"CryptEncrypt", "CryptDecrypt", "RtlDecompressBuffer"},
    "反调试": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString"}
}

# --- Known system DLLs ---
KNOWN_DLLS = {
    "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll",
    "ole32.dll", "oleaut32.dll", "ws2_32.dll", "version.dll", "combase.dll",
    "rpcrt4.dll", "sechost.dll", "shlwapi.dll", "ucrtbase.dll"
}
