# -*- coding: utf-8 -*-
"""
luodllhack/dll_hijack/emitters.py
Code emitters for generating proxy DLL files.
"""

import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from luodllhack.core.signatures.models import FunctionSignature as ExportSymbol, CallingConvention
from .models import PEInfo, VersionInfo
from .interfaces import CodeEmitter
from .utils import resolve_forwarder_module


class DefFileEmitter(CodeEmitter):
    """Generates .def module definition files.

    DEF file EXPORTS syntax:
        entryname[=internalname] [@ordinal [NONAME]] [PRIVATE] [DATA]

    Supports two modes:
        - Forwarder mode: FuncName = orig.FuncName (static forwarding)
        - Dynamic mode: FuncName = _proxy_FuncName (runtime hooks)
    """

    def __init__(self, mode: str = 'forwarder'):
        """
        Args:
            mode: 'forwarder' for static forwarding to orig DLL,
                  'dynamic' for internal _proxy_* functions
        """
        self._mode = mode

    def get_file_extensions(self) -> List[str]:
        return ['.def']

    def emit(self, pe_info: PEInfo, output_dir: Path) -> List[Path]:
        dll_name = pe_info.path.stem.lower()

        if self._mode == 'dynamic':
            def_path = output_dir / f"proxy_{dll_name}_dynamic.def"
            mode_desc = "Dynamic (hooks to _proxy_* functions)"
        else:
            def_path = output_dir / f"proxy_{dll_name}.def"
            mode_desc = "Forwarder (static forwarding to orig DLL)"

        lines = [
            f"; Module definition file for {dll_name}.dll proxy",
            f"; Architecture: {pe_info.arch_name}",
            f"; Mode: {mode_desc}",
            f"; Exports: {len(pe_info.exports)}",
            "",
            f"LIBRARY {dll_name}",
            "",
            "EXPORTS"
        ]

        for exp in pe_info.exports:
            line = self._format_export(exp, dll_name)
            if line:
                lines.append(line)

        def_path.write_text("\n".join(lines), encoding="utf-8")
        return [def_path]

    def _format_export(self, exp: ExportSymbol, dll_name: str) -> str:
        """Format a single export entry for .def file."""
        # Skip DATA exports in dynamic mode (can't hook data)
        if exp.is_data and self._mode == 'dynamic':
            return ""

        # Safe name for C identifier
        safe_name = exp.name if exp.name else f"ordinal_{exp.ordinal}"
        safe_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in safe_name)

        # Determine target based on mode
        if self._mode == 'dynamic':
            # Dynamic mode: export points to internal _proxy_* function
            if exp.is_named:
                target = f"_proxy_{safe_name}"
            else:
                target = f"__exp_{exp.ordinal}_impl"
        else:
            # Forwarder mode: export forwards to orig DLL
            orig_dll = f"{dll_name}_orig"
            if exp.is_forwarded:
                target = self._resolve_forwarder(exp.forwarder)
            elif exp.is_named:
                target = f"{orig_dll}.{exp.name}"
            else:
                target = f"{orig_dll}.#{exp.ordinal}"

        # Build the export line parts
        parts = []

        # Entry name
        if exp.is_named:
            entry_name = exp.name
        else:
            entry_name = f"__exp_ord_{exp.ordinal}"

        parts.append(f"    {entry_name} = {target}")

        if exp.ordinal:
            parts.append(f"@{exp.ordinal}")

        if not exp.is_named:
            parts.append("NONAME")

        if exp.is_data and self._mode != 'dynamic':
            parts.append("DATA")

        return " ".join(parts)

    def _resolve_forwarder(self, forwarder: str) -> str:
        """Resolve forwarder string to actual module.function format."""
        if '.' in forwarder:
            mod, rest = forwarder.split('.', 1)
        else:
            mod, rest = forwarder, ''
        mod_resolved = resolve_forwarder_module(mod)
        return f"{mod_resolved}.{rest}" if rest else mod_resolved


class CCodeEmitter(CodeEmitter):
    """Generates C source code for proxy DLL with payload hooks.

    Generates correct #pragma comment(linker, "/EXPORT:...") syntax for all export types:
    - Named exports: /EXPORT:name=target.name
    - Ordinal exports: /EXPORT:name=target.#ordinal,@ordinal,NONAME
    - Forwarded exports: resolved to actual target
    - Data exports: appends ,DATA flag
    """

    HEADER_TEMPLATE = '''// =============================================================================
// Auto-generated Proxy DLL for {dll_name}.dll
// Architecture: {arch}
// Generated: {timestamp}
// =============================================================================

#include <windows.h>

// -----------------------------------------------------------------------------
// 安全加载标志 (兼容旧版 Windows SDK)
// -----------------------------------------------------------------------------
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------
#define ORIG_DLL_NAME L"{dll_name}_orig.dll"
#define LOAD_FLAGS    {load_flags}

// -----------------------------------------------------------------------------
// Global State
// -----------------------------------------------------------------------------
static HMODULE g_hOriginalDll = NULL;
static BOOL    g_bInitialized = FALSE;
'''

    PAYLOAD_HOOK_TEMPLATE = '''
// =============================================================================
// PAYLOAD HOOKS - Implement your custom logic here
// =============================================================================

// Called once when the proxy DLL is first loaded
// Return TRUE to continue loading, FALSE to abort
static BOOL OnProxyAttach(HMODULE hModule)
{{
    // TODO: Add your initialization code here
    // Example: Start a thread, hook functions, etc.

    return TRUE;
}}

// Called when a process is about to use the DLL
// This is called after the original DLL is loaded
static void OnProcessAttach(void)
{{
    // TODO: Add your per-process initialization here
}}

// Called when the DLL is being unloaded
static void OnProxyDetach(void)
{{
    // TODO: Add your cleanup code here
}}
'''

    DLLMAIN_TEMPLATE = '''
// =============================================================================
// DLL Entry Point
// =============================================================================

// 安全加载原始 DLL (防止 DLL 搜索路径注入)
static HMODULE LoadOriginalDllSecurely(void)
{{
    HMODULE hDll = NULL;
    wchar_t sysPath[MAX_PATH];

    // 方法1: 使用安全标志从 System32 加载 (Windows 8+)
    hDll = LoadLibraryExW(L"{dll_name}.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hDll) return hDll;

    // 方法2: 构建 System32 绝对路径加载 (兼容旧版 Windows)
    if (GetSystemDirectoryW(sysPath, MAX_PATH) > 0)
    {{
        wcscat_s(sysPath, MAX_PATH, L"\\\\{dll_name}.dll");
        hDll = LoadLibraryW(sysPath);
        if (hDll) return hDll;
    }}

    // 方法3: 尝试同目录下的 _orig 版本 (代理场景)
    hDll = LoadLibraryW(ORIG_DLL_NAME);

    return hDll;
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{{
    switch (dwReason)
    {{
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        // Call payload hook first
        if (!OnProxyAttach(hModule))
        {{
            return FALSE;
        }}

        // 安全加载原始 DLL
        g_hOriginalDll = LoadOriginalDllSecurely();

        if (g_hOriginalDll)
        {{
            g_bInitialized = TRUE;
            OnProcessAttach();
        }}
        break;

    case DLL_PROCESS_DETACH:
        OnProxyDetach();
        if (g_hOriginalDll)
        {{
            FreeLibrary(g_hOriginalDll);
            g_hOriginalDll = NULL;
        }}
        g_bInitialized = FALSE;
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }}

    return g_hOriginalDll != NULL || dwReason == DLL_PROCESS_DETACH;
}}
'''

    def get_file_extensions(self) -> List[str]:
        return ['.c', '.h']

    def emit(self, pe_info: PEInfo, output_dir: Path) -> List[Path]:
        dll_name = pe_info.path.stem.lower()
        c_path = output_dir / f"proxy_{dll_name}.c"

        lines = []

        # Header
        lines.append(self.HEADER_TEMPLATE.format(
            dll_name=dll_name,
            arch=pe_info.arch_name,
            timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            load_flags='LOAD_LIBRARY_SEARCH_SYSTEM32'
        ))

        # Export declarations
        lines.append("// -----------------------------------------------------------------------------")
        lines.append("// Export Forwarding Declarations")
        lines.append("// -----------------------------------------------------------------------------")
        lines.append("")

        for exp in pe_info.exports:
            export_line = self._format_export_pragma(exp, dll_name)
            if export_line:
                lines.append(export_line)

        # Payload hooks
        lines.append(self.PAYLOAD_HOOK_TEMPLATE)

        # DllMain
        lines.append(self.DLLMAIN_TEMPLATE.format(dll_name=dll_name))

        c_path.write_text("\n".join(lines), encoding="utf-8")
        return [c_path]

    def _format_export_pragma(self, exp: ExportSymbol, dll_name: str) -> str:
        """Generate correct #pragma comment(linker, "/EXPORT:...") syntax."""
        orig_dll = f"{dll_name}_orig"

        # Determine target
        if exp.is_forwarded:
            target = self._resolve_forwarder(exp.forwarder)
        else:
            if exp.is_named:
                target = f"{orig_dll}.{exp.name}"
            else:
                target = f"{orig_dll}.#{exp.ordinal}"

        # Build export specification parts
        parts = []

        # Entry name
        if exp.is_named:
            entry_name = exp.name
        else:
            entry_name = f"__export_ord_{exp.ordinal}"

        parts.append(f"{entry_name}={target}")

        if exp.ordinal:
            parts.append(f"@{exp.ordinal}")

        if not exp.is_named:
            parts.append("NONAME")

        if exp.is_data:
            parts.append("DATA")

        export_spec = ",".join(parts)
        return f'#pragma comment(linker, "/EXPORT:{export_spec}")'

    def _resolve_forwarder(self, forwarder: str) -> str:
        if '.' in forwarder:
            mod, rest = forwarder.split('.', 1)
        else:
            mod, rest = forwarder, ''
        mod_resolved = resolve_forwarder_module(mod)
        return f"{mod_resolved}.{rest}" if rest else mod_resolved


class DynamicProxyEmitter(CodeEmitter):
    """Generates dynamic proxy DLL with full argument forwarding.

    Features:
    - Complete argument preservation using assembly trampolines
    - Multi-compiler support (MSVC, MinGW, Clang)
    - Pre/Post hook callbacks
    - x86/x64/ARM64 architecture support
    - Thread-safe lazy initialization
    """

    def __init__(self, compiler: str = "msvc", enable_hooks: bool = True):
        """Initialize emitter.

        Args:
            compiler: Target compiler ("msvc", "mingw", "clang")
            enable_hooks: Generate hook callback support
        """
        self._compiler = compiler.lower()
        self._enable_hooks = enable_hooks

    def get_file_extensions(self) -> List[str]:
        return ['.c', '.asm']

    def emit(self, pe_info: PEInfo, output_dir: Path) -> List[Path]:
        dll_name = pe_info.path.stem.lower()
        created_files = []

        # Main C file
        c_path = output_dir / f"proxy_{dll_name}_dynamic.c"
        c_content = self._generate_c_file(pe_info, dll_name)
        c_path.write_text(c_content, encoding="utf-8")
        created_files.append(c_path)

        # ASM file for full forwarding (x64 needs external asm for naked functions)
        if pe_info.is_64bit and self._compiler == "msvc":
            asm_path = output_dir / f"proxy_{dll_name}_asm.asm"
            asm_content = self._generate_asm_file(pe_info, dll_name)
            asm_path.write_text(asm_content, encoding="utf-8")
            created_files.append(asm_path)

        return created_files

    def _generate_c_file(self, pe_info: PEInfo, dll_name: str) -> str:
        """Generate main C source file."""
        lines = []

        # Header
        lines.append(self._get_header(dll_name, pe_info.arch_name))

        # Function pointer declarations
        lines.append(self._get_function_pointers_section(pe_info))

        # Hook system
        if self._enable_hooks:
            lines.append(self._get_hook_system())

        # Initialization
        lines.append(self._get_init_function(pe_info))

        # Wrapper functions
        lines.append(self._get_wrapper_functions(pe_info, dll_name))

        # DllMain
        lines.append(self._get_dllmain(dll_name, pe_info))

        return "\n".join(lines)

    def _get_header(self, dll_name: str, arch: str) -> str:
        """Generate file header."""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Compiler-specific defines
        if self._compiler == "mingw":
            compiler_defines = '''
// MinGW compatibility
#define PROXY_MINGW 1
#ifndef __cdecl
#define __cdecl
#endif
'''
        else:
            compiler_defines = '''
// MSVC
#define PROXY_MSVC 1
'''

        return f'''// =============================================================================
// Dynamic Proxy DLL - Full Argument Forwarding
// Target: {dll_name}.dll
// Architecture: {arch}
// Compiler: {self._compiler.upper()}
// Generated: {timestamp}
// =============================================================================

#include <windows.h>
#include <stdio.h>
#include <intrin.h>
{compiler_defines}
// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------
#define ORIG_DLL_NAME L"{dll_name}_orig.dll"
#define PROXY_ENABLE_LOGGING 1

#if PROXY_ENABLE_LOGGING
  #ifdef PROXY_MINGW
    #define PROXY_LOG(fmt, ...) do {{ \\
        char _buf[512]; \\
        snprintf(_buf, sizeof(_buf), "[PROXY] " fmt "\\n", ##__VA_ARGS__); \\
        OutputDebugStringA(_buf); \\
    }} while(0)
  #else
    #define PROXY_LOG(fmt, ...) do {{ \\
        char _buf[512]; \\
        _snprintf_s(_buf, sizeof(_buf), _TRUNCATE, "[PROXY] " fmt "\\n", ##__VA_ARGS__); \\
        OutputDebugStringA(_buf); \\
    }} while(0)
  #endif
#else
  #define PROXY_LOG(fmt, ...) ((void)0)
#endif

// -----------------------------------------------------------------------------
// Global State
// -----------------------------------------------------------------------------
static HMODULE g_hOriginalDll = NULL;
static volatile LONG g_bInitialized = FALSE;
static CRITICAL_SECTION g_InitLock;
'''

    def _get_function_pointers_section(self, pe_info: PEInfo) -> str:
        """Generate function pointer declarations."""
        lines = ['''
// -----------------------------------------------------------------------------
// Original Function Pointers
// -----------------------------------------------------------------------------
typedef void* (*GenericFuncPtr)(void);
''']

        for exp in pe_info.exports:
            if not exp.is_data:
                safe_name = exp.get_safe_c_name()
                lines.append(f"static GenericFuncPtr orig_{safe_name} = NULL;")

        return "\n".join(lines)

    def _get_hook_system(self) -> str:
        """Generate hook callback system."""
        return '''
// =============================================================================
// Hook System
// =============================================================================

// Hook context passed to callbacks
typedef struct _HOOK_CONTEXT {
    const char* funcName;      // Function name
    void*       returnAddress; // Caller return address
    void*       stackPtr;      // Stack pointer at call
    BOOL        skipCall;      // Set TRUE to skip original call
    void*       overrideResult;// If skipCall, return this value
} HOOK_CONTEXT;

// Hook callback types
typedef void (*PreHookFunc)(HOOK_CONTEXT* ctx);
typedef void (*PostHookFunc)(HOOK_CONTEXT* ctx, void* result);

static PreHookFunc  g_PreHook  = NULL;
static PostHookFunc g_PostHook = NULL;

// Public API to set hooks
__declspec(dllexport) void SetProxyHooks(PreHookFunc pre, PostHookFunc post)
{
    g_PreHook = pre;
    g_PostHook = post;
    PROXY_LOG("Hooks installed: Pre=%p Post=%p", pre, post);
}

// Called once on DLL load
static BOOL OnProxyAttach(HMODULE hModule)
{
    PROXY_LOG("Proxy DLL attached (Module: %p)", hModule);
    // TODO: Initialize your hooks here
    return TRUE;
}

static void OnProxyDetach(void)
{
    PROXY_LOG("Proxy DLL detaching");
}
'''

    def _get_init_function(self, pe_info: PEInfo) -> str:
        """Generate initialization function with resolve code."""
        resolve_lines = []
        for exp in pe_info.exports:
            if not exp.is_data:
                safe_name = exp.get_safe_c_name()
                if exp.is_named:
                    resolve_lines.append(
                        f'    orig_{safe_name} = (GenericFuncPtr)GetProcAddress(g_hOriginalDll, "{exp.name}");'
                    )
                else:
                    resolve_lines.append(
                        f'    orig_{safe_name} = (GenericFuncPtr)GetProcAddress(g_hOriginalDll, MAKEINTRESOURCEA({exp.ordinal}));'
                    )

        resolve_code = "\n".join(resolve_lines)

        return f'''
// -----------------------------------------------------------------------------
// 安全加载原始 DLL (防止 DLL 搜索路径注入)
// -----------------------------------------------------------------------------
static HMODULE LoadOriginalDllSecurely(void)
{{
    HMODULE hDll = NULL;
    wchar_t sysPath[MAX_PATH];

    // 方法1: 使用安全标志从 System32 加载 (Windows 8+)
    hDll = LoadLibraryExW(L"{pe_info.path.stem.lower()}.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hDll) return hDll;

    // 方法2: 构建 System32 绝对路径加载 (兼容旧版 Windows)
    if (GetSystemDirectoryW(sysPath, MAX_PATH) > 0)
    {{
        wcscat_s(sysPath, MAX_PATH, L"\\\\{pe_info.path.stem.lower()}.dll");
        hDll = LoadLibraryW(sysPath);
        if (hDll) return hDll;
    }}

    // 方法3: 尝试同目录下的 _orig 版本 (代理场景)
    hDll = LoadLibraryW(ORIG_DLL_NAME);

    return hDll;
}}

// -----------------------------------------------------------------------------
// Lazy Initialization
// -----------------------------------------------------------------------------
static __forceinline BOOL EnsureInitialized(void)
{{
    if (InterlockedCompareExchange(&g_bInitialized, FALSE, FALSE)) return TRUE;

    EnterCriticalSection(&g_InitLock);
    if (g_bInitialized) {{
        LeaveCriticalSection(&g_InitLock);
        return TRUE;
    }}

    // 安全加载原始 DLL
    g_hOriginalDll = LoadOriginalDllSecurely();

    if (!g_hOriginalDll) {{
        PROXY_LOG("FATAL: Failed to load original DLL (Error: %lu)", GetLastError());
        LeaveCriticalSection(&g_InitLock);
        return FALSE;
    }}

    PROXY_LOG("Original DLL loaded: %p", g_hOriginalDll);

    // Resolve exports
{resolve_code}

    InterlockedExchange(&g_bInitialized, TRUE);
    LeaveCriticalSection(&g_InitLock);
    return TRUE;
}}
'''

    def _get_wrapper_functions(self, pe_info: PEInfo, dll_name: str) -> str:
        """Generate wrapper functions with full argument forwarding."""
        lines = ['''
// =============================================================================
// Exported Wrapper Functions
// =============================================================================
''']

        for exp in pe_info.exports:
            if exp.is_data:
                continue

            safe_name = exp.get_safe_c_name()
            export_name = exp.name if exp.is_named else f"ordinal_{exp.ordinal}"

            # Export pragma
            if exp.is_named:
                pragma = f'#pragma comment(linker, "/EXPORT:{exp.name}=_proxy_{safe_name}")'
            else:
                pragma = f'#pragma comment(linker, "/EXPORT:__exp_{exp.ordinal}=_proxy_{safe_name},@{exp.ordinal},NONAME")'

            if pe_info.is_64bit:
                # x64: Use varargs trick for full forwarding
                lines.append(self._generate_x64_wrapper(exp, safe_name, export_name, pragma))
            elif pe_info.is_arm64:
                # ARM64
                lines.append(self._generate_arm64_wrapper(exp, safe_name, export_name, pragma))
            else:
                # x86: Use naked function
                lines.append(self._generate_x86_wrapper(exp, safe_name, export_name, pragma))

        return "\n".join(lines)

    def _generate_x64_wrapper(self, exp: ExportSymbol, safe_name: str, export_name: str, pragma: str) -> str:
        """Generate x64 wrapper with full argument forwarding."""
        if self._compiler == "msvc":
            # MSVC x64: All named exports use internal function name + pragma alias
            # This avoids conflicts with Windows SDK headers (e.g., CreatePropertySheetPageA in prsht.h)
            # __declspec(dllexport) ensures the internal symbol is visible to the linker

            if exp.is_named:
                # Named export: use internal function name (_proxy_*)
                # Export is defined in DEF file, not via pragma (avoids LNK2001)
                return f'''
// x64 wrapper - {exp.name} (exported via DEF file)
void* __cdecl _proxy_{safe_name}(
    void* rcx, void* rdx, void* r8, void* r9,
    void* stk1, void* stk2, void* stk3, void* stk4,
    void* stk5, void* stk6, void* stk7, void* stk8)
{{
    if (!EnsureInitialized()) return NULL;
    if (!orig_{safe_name}) return NULL;

    PROXY_LOG("-> {export_name}");

    // Call original with all args
    typedef void* (*FullFunc)(void*,void*,void*,void*,void*,void*,void*,void*,void*,void*,void*,void*);
    return ((FullFunc)orig_{safe_name})(rcx, rdx, r8, r9, stk1, stk2, stk3, stk4, stk5, stk6, stk7, stk8);
}}
'''
            else:
                # Ordinal-only export: use internal function name
                # Export is defined in DEF file, not via pragma
                return f'''
// x64 wrapper - ordinal {exp.ordinal} (exported via DEF file)
void* __cdecl __exp_{exp.ordinal}_impl(
    void* rcx, void* rdx, void* r8, void* r9,
    void* stk1, void* stk2, void* stk3, void* stk4,
    void* stk5, void* stk6, void* stk7, void* stk8)
{{
    if (!EnsureInitialized()) return NULL;
    if (!orig_{safe_name}) return NULL;

    PROXY_LOG("-> ordinal_{exp.ordinal}");

    // Call original with all args
    typedef void* (*FullFunc)(void*,void*,void*,void*,void*,void*,void*,void*,void*,void*,void*,void*);
    return ((FullFunc)orig_{safe_name})(rcx, rdx, r8, r9, stk1, stk2, stk3, stk4, stk5, stk6, stk7, stk8);
}}
'''
        else:
            # MinGW/Clang x64: 使用 GCC 扩展语法
            # x64 ABI: 调用前 RSP 必须 16 字节对齐
            # call 指令后 RSP = 原始-8，需要 sub 0x28 使 RSP 对齐 (8+0x28=0x30, 0x30 mod 16 = 0)
            return f'''
// MinGW x64 wrapper - 完整参数转发
__attribute__((naked)) void* _proxy_{safe_name}(void)
{{
    __asm__ __volatile__ (
        "push %%rbp\\n\\t"
        "mov %%rsp, %%rbp\\n\\t"
        "sub $0x20, %%rsp\\n\\t"          // 32 字节 shadow space, 16 字节对齐
        "call EnsureInitialized\\n\\t"    // x64 无前导下划线
        "test %%eax, %%eax\\n\\t"
        "jz 1f\\n\\t"
        "mov %0, %%rax\\n\\t"             // 使用内存约束加载函数指针
        "test %%rax, %%rax\\n\\t"
        "jz 1f\\n\\t"
        "add $0x20, %%rsp\\n\\t"
        "pop %%rbp\\n\\t"
        "jmp *%%rax\\n\\t"                // 尾调用跳转
        "1:\\n\\t"
        "xor %%eax, %%eax\\n\\t"
        "add $0x20, %%rsp\\n\\t"
        "pop %%rbp\\n\\t"
        "ret\\n\\t"
        : : "m" (orig_{safe_name})        // 内存约束引用全局变量
    );
}}
'''

    def _generate_x86_wrapper(self, exp: ExportSymbol, safe_name: str, export_name: str, pragma: str) -> str:
        """Generate x86 wrapper with full argument forwarding."""
        cc = exp.calling_convention
        cc_keyword = {
            CallingConvention.CDECL: "__cdecl",
            CallingConvention.STDCALL: "__stdcall",
            CallingConvention.FASTCALL: "__fastcall",
            CallingConvention.THISCALL: "__thiscall",
        }.get(cc, "__stdcall")

        if self._compiler == "msvc":
            return f'''
{pragma}
__declspec(naked) void {cc_keyword} _proxy_{safe_name}(void)
{{
    __asm {{
        // Preserve all registers
        push ebp
        mov ebp, esp
        pushad
        pushfd

        // Initialize if needed
        call EnsureInitialized
        test eax, eax
        jz _fail_{safe_name}

        // Check function pointer
        mov eax, dword ptr [orig_{safe_name}]
        test eax, eax
        jz _fail_{safe_name}

        // Restore and jump
        popfd
        popad
        pop ebp
        jmp dword ptr [orig_{safe_name}]

    _fail_{safe_name}:
        popfd
        popad
        pop ebp
        xor eax, eax
        ret
    }}
}}
'''
        else:
            # MinGW x86: 使用 GCC 扩展语法引用 C 变量
            # 通过 "m" 约束让编译器处理符号引用
            return f'''
// MinGW x86 wrapper - 使用 GCC 扩展语法
__attribute__((naked)) void _proxy_{safe_name}(void)
{{
    __asm__ __volatile__ (
        "push %%ebp\\n\\t"
        "mov %%esp, %%ebp\\n\\t"
        "pusha\\n\\t"
        "pushf\\n\\t"
        "call _EnsureInitialized\\n\\t"   // MinGW x86 需要前导下划线
        "test %%eax, %%eax\\n\\t"
        "jz 1f\\n\\t"
        "mov %0, %%eax\\n\\t"             // 通过内存约束访问
        "test %%eax, %%eax\\n\\t"
        "jz 1f\\n\\t"
        "popf\\n\\t"
        "popa\\n\\t"
        "pop %%ebp\\n\\t"
        "jmp *%0\\n\\t"                   // 间接跳转
        "1:\\n\\t"
        "popf\\n\\t"
        "popa\\n\\t"
        "pop %%ebp\\n\\t"
        "xor %%eax, %%eax\\n\\t"
        "ret\\n\\t"
        : : "m" (orig_{safe_name})        // 内存约束
    );
}}
'''

    def _generate_arm64_wrapper(self, exp: ExportSymbol, safe_name: str, export_name: str, pragma: str) -> str:
        """Generate ARM64 wrapper."""
        return f'''
// ARM64 wrapper for {export_name}
{pragma}
void* _proxy_{safe_name}(
    void* x0, void* x1, void* x2, void* x3,
    void* x4, void* x5, void* x6, void* x7)
{{
    if (!EnsureInitialized()) return NULL;
    if (!orig_{safe_name}) return NULL;

    PROXY_LOG("-> {export_name}");

    typedef void* (*ArmFunc)(void*,void*,void*,void*,void*,void*,void*,void*);
    return ((ArmFunc)orig_{safe_name})(x0, x1, x2, x3, x4, x5, x6, x7);
}}
'''

    def _get_dllmain(self, dll_name: str, pe_info: PEInfo) -> str:
        """Generate DllMain."""
        tls_code = ""
        if pe_info.has_tls:
            tls_code = '''
        // Forward TLS callbacks
        // Note: Original DLL TLS callbacks will run when it's loaded
'''

        return f'''
// =============================================================================
// Entry Point
// =============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{{
    (void)lpReserved;

    switch (dwReason)
    {{
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_InitLock);
{tls_code}
        if (!OnProxyAttach(hModule)) {{
            return FALSE;
        }}
        break;

    case DLL_PROCESS_DETACH:
        OnProxyDetach();
        if (g_hOriginalDll) {{
            FreeLibrary(g_hOriginalDll);
            g_hOriginalDll = NULL;
        }}
        DeleteCriticalSection(&g_InitLock);
        InterlockedExchange(&g_bInitialized, FALSE);
        break;
    }}

    return TRUE;
}}
'''

    def _generate_asm_file(self, pe_info: PEInfo, dll_name: str) -> str:
        """Generate MASM assembly file for x64 perfect forwarding."""
        lines = [f'''; =============================================================================
; Assembly trampolines for {dll_name}.dll proxy
; Architecture: x64
; Assembler: MASM (ml64.exe)
; =============================================================================

.code

EXTERN EnsureInitialized:PROC
''']

        # Extern declarations for function pointers
        for exp in pe_info.exports:
            if not exp.is_data:
                safe_name = exp.get_safe_c_name()
                lines.append(f"EXTERN orig_{safe_name}:QWORD")

        lines.append("")

        # Generate trampolines
        for exp in pe_info.exports:
            if exp.is_data:
                continue

            safe_name = exp.get_safe_c_name()
            # x64 ABI: 调用者保存 RCX, RDX, R8, R9, 被调用者需要 32 字节 shadow space
            # 入口时 RSP = 原始-8 (call 压入返回地址)
            # 需要 sub rsp, 0x28 对齐到 16 字节并预留 shadow space
            lines.append(f'''
; Trampoline for {exp.name or f'ordinal {exp.ordinal}'}
asm_trampoline_{safe_name} PROC
    ; 保存被调用者保存的寄存器
    push rbx
    push rsi
    push rdi
    sub rsp, 20h                    ; shadow space (32 bytes)

    ; 初始化检查
    call EnsureInitialized
    test eax, eax
    jz @fail_{safe_name}

    ; 检查函数指针
    mov rax, QWORD PTR [orig_{safe_name}]
    test rax, rax
    jz @fail_{safe_name}

    ; 恢复栈和寄存器
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx

    ; 尾调用跳转 (参数仍在原始位置)
    jmp QWORD PTR [orig_{safe_name}]

@fail_{safe_name}:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    xor eax, eax
    ret
asm_trampoline_{safe_name} ENDP
''')

        lines.append("\nEND")
        return "\n".join(lines)


class CppExportEmitter(CodeEmitter):
    """Handles C++ decorated exports with name demangling.

    Features:
    - MSVC and GCC name demangling
    - Virtual table (vtable) proxy generation
    - Class method forwarding
    - Operator overload handling
    """

    def __init__(self):
        self._undname_available = self._check_undname()

    def _check_undname(self) -> bool:
        """Check if undname.exe is available."""
        import shutil
        return shutil.which("undname") is not None

    def get_file_extensions(self) -> List[str]:
        return ['.cpp', '.h']

    def emit(self, pe_info: PEInfo, output_dir: Path) -> List[Path]:
        """Generate C++ proxy code for decorated exports."""
        # Filter C++ exports
        cpp_exports = [e for e in pe_info.exports if e.is_cpp_mangled]

        if not cpp_exports:
            return []  # No C++ exports

        dll_name = pe_info.path.stem.lower()
        created_files = []

        # Generate header with demangled declarations
        h_path = output_dir / f"proxy_{dll_name}_cpp.h"
        h_content = self._generate_header(cpp_exports, dll_name, pe_info)
        h_path.write_text(h_content, encoding="utf-8")
        created_files.append(h_path)

        # Generate implementation
        cpp_path = output_dir / f"proxy_{dll_name}_cpp.cpp"
        cpp_content = self._generate_cpp(cpp_exports, dll_name, pe_info)
        cpp_path.write_text(cpp_content, encoding="utf-8")
        created_files.append(cpp_path)

        return created_files

    def _demangle_name(self, mangled: str) -> str:
        """Demangle a C++ decorated name."""
        if not mangled:
            return mangled

        # Try Windows UnDecorateSymbolName
        try:
            import ctypes
            dbghelp = ctypes.windll.dbghelp
            buffer = ctypes.create_string_buffer(1024)
            result = dbghelp.UnDecorateSymbolName(
                mangled.encode(),
                buffer,
                1024,
                0  # UNDNAME_COMPLETE
            )
            if result:
                return buffer.value.decode()
        except Exception:
            pass

        # Fallback: basic pattern recognition
        if mangled.startswith("?"):
            # Extract function name from MSVC mangling
            parts = mangled[1:].split("@")
            if parts:
                return parts[0]

        return mangled

    def _generate_header(self, cpp_exports: List[ExportSymbol], dll_name: str, pe_info: PEInfo) -> str:
        """Generate header file with C++ declarations."""
        lines = [f'''// =============================================================================
// C++ Export Declarations for {dll_name}.dll
// Architecture: {pe_info.arch_name}
// C++ Exports: {len(cpp_exports)}
// =============================================================================

#pragma once

#include <windows.h>

// Original DLL handle
extern HMODULE g_hOriginalDll;

// Demangled export declarations
''']

        for exp in cpp_exports:
            demangled = self._demangle_name(exp.name)
            lines.append(f"// {exp.name}")
            lines.append(f"// -> {demangled}")
            lines.append(f"extern void* orig_{exp.get_safe_c_name()};")
            lines.append("")

        return "\n".join(lines)

    def _generate_cpp(self, cpp_exports: List[ExportSymbol], dll_name: str, pe_info: PEInfo) -> str:
        """Generate C++ implementation file."""
        lines = [f'''// =============================================================================
// C++ Export Forwarding for {dll_name}.dll
// =============================================================================

#include "proxy_{dll_name}_cpp.h"
#include <cstdio>

// Function pointer storage
''']

        for exp in cpp_exports:
            safe_name = exp.get_safe_c_name()
            lines.append(f"void* orig_{safe_name} = nullptr;")

        lines.append('''
// Resolution function
void ResolveCppExports(HMODULE hDll)
{
''')

        for exp in cpp_exports:
            safe_name = exp.get_safe_c_name()
            # C++ names need special handling for GetProcAddress
            lines.append(f'    orig_{safe_name} = GetProcAddress(hDll, "{exp.name}");')

        lines.append('''}

// =============================================================================
// Export Forwarding
// Note: C++ exports preserve exact name mangling
// =============================================================================
''')

        # Generate pragma exports that preserve the mangled name
        for exp in cpp_exports:
            safe_name = exp.get_safe_c_name()
            demangled = self._demangle_name(exp.name)

            lines.append(f'''
// {demangled}
#pragma comment(linker, "/EXPORT:{exp.name}=proxy_{safe_name}")
extern "C" void* proxy_{safe_name}()
{{
    if (!orig_{safe_name}) return nullptr;
    // Forward via jump (actual implementation in ASM)
    return orig_{safe_name};
}}
''')

        return "\n".join(lines)


class ResourceEmitter(CodeEmitter):
    """Generates resource file (.rc) with version info from original DLL.

    Features:
    - Copies VERSION_INFO from original DLL
    - Generates .rc file for compilation
    - Preserves file description, company, etc.
    """

    def get_file_extensions(self) -> List[str]:
        return ['.rc']

    def emit(self, pe_info: PEInfo, output_dir: Path) -> List[Path]:
        """Generate resource file with version info."""
        if not pe_info.version_info:
            # Try to extract version info
            version_info = self._extract_version_info(pe_info.path)
            if not version_info:
                return []
        else:
            version_info = pe_info.version_info

        dll_name = pe_info.path.stem.lower()
        rc_path = output_dir / f"proxy_{dll_name}.rc"

        rc_content = self._generate_rc(version_info, dll_name)
        rc_path.write_text(rc_content, encoding="utf-8")

        return [rc_path]

    def _extract_version_info(self, dll_path: Path) -> Optional['VersionInfo']:
        """Extract version info from PE file."""
        try:
            import pefile
            pe = pefile.PE(str(dll_path))

            if not hasattr(pe, 'VS_FIXEDFILEINFO') and not hasattr(pe, 'FileInfo'):
                return None

            from .models import VersionInfo
            info = VersionInfo()

            # Get string file info
            if hasattr(pe, 'FileInfo'):
                for fileinfo in pe.FileInfo:
                    for entry in fileinfo:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                for key, value in st.entries.items():
                                    key_str = key.decode() if isinstance(key, bytes) else key
                                    val_str = value.decode() if isinstance(value, bytes) else value

                                    if key_str == 'CompanyName':
                                        info.company_name = val_str
                                    elif key_str == 'FileDescription':
                                        info.file_description = val_str
                                    elif key_str == 'FileVersion':
                                        info.file_version = val_str
                                    elif key_str == 'InternalName':
                                        info.internal_name = val_str
                                    elif key_str == 'OriginalFilename':
                                        info.original_filename = val_str
                                    elif key_str == 'ProductName':
                                        info.product_name = val_str
                                    elif key_str == 'ProductVersion':
                                        info.product_version = val_str
                                    elif key_str == 'LegalCopyright':
                                        info.legal_copyright = val_str

            # Get fixed file info for version numbers
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                ffi = pe.VS_FIXEDFILEINFO[0]
                if not info.file_version:
                    major = (ffi.FileVersionMS >> 16) & 0xFFFF
                    minor = ffi.FileVersionMS & 0xFFFF
                    patch = (ffi.FileVersionLS >> 16) & 0xFFFF
                    build = ffi.FileVersionLS & 0xFFFF
                    info.file_version = f"{major}.{minor}.{patch}.{build}"

            return info

        except Exception:
            return None

    def _generate_rc(self, info: 'VersionInfo', dll_name: str) -> str:
        """Generate .rc resource file content."""
        # Parse version numbers
        version_parts = info.file_version.split('.') if info.file_version else ['1', '0', '0', '0']
        while len(version_parts) < 4:
            version_parts.append('0')

        version_comma = ','.join(version_parts[:4])

        return f'''// =============================================================================
// Resource file for {dll_name}.dll proxy
// Auto-generated from original DLL
// =============================================================================

#include <windows.h>

VS_VERSION_INFO VERSIONINFO
FILEVERSION {version_comma}
PRODUCTVERSION {version_comma}
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_DLL
FILESUBTYPE VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "{info.company_name or 'Unknown'}"
            VALUE "FileDescription", "{info.file_description or dll_name}"
            VALUE "FileVersion", "{info.file_version or '1.0.0.0'}"
            VALUE "InternalName", "{info.internal_name or dll_name}"
            VALUE "LegalCopyright", "{info.legal_copyright or ''}"
            VALUE "OriginalFilename", "{info.original_filename or dll_name + '.dll'}"
            VALUE "ProductName", "{info.product_name or dll_name}"
            VALUE "ProductVersion", "{info.product_version or info.file_version or '1.0.0.0'}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
'''


class TLSCallbackEmitter(CodeEmitter):
    """Generates TLS callback handling code.

    TLS (Thread Local Storage) callbacks are called before DllMain.
    Some DLLs use them for initialization or anti-debugging.
    """

    def get_file_extensions(self) -> List[str]:
        return ['.c']

    def emit(self, pe_info: PEInfo, output_dir: Path) -> List[Path]:
        """Generate TLS callback forwarding code."""
        if not pe_info.has_tls or not pe_info.tls_callbacks:
            return []

        dll_name = pe_info.path.stem.lower()
        c_path = output_dir / f"proxy_{dll_name}_tls.c"

        c_content = self._generate_tls_code(pe_info, dll_name)
        c_path.write_text(c_content, encoding="utf-8")

        return [c_path]

    def _generate_tls_code(self, pe_info: PEInfo, dll_name: str) -> str:
        """Generate TLS callback code."""
        return f'''// =============================================================================
// TLS Callback Handling for {dll_name}.dll
// Original TLS callbacks: {len(pe_info.tls_callbacks)}
// =============================================================================

#include <windows.h>

// TLS callback function type
typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved);

// Our TLS callback - runs before DllMain
VOID NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{{
    switch (Reason)
    {{
    case DLL_PROCESS_ATTACH:
        // Called before DllMain for process attach
        OutputDebugStringA("[PROXY-TLS] Process attach\\n");
        break;

    case DLL_THREAD_ATTACH:
        // Called for each new thread
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        OutputDebugStringA("[PROXY-TLS] Process detach\\n");
        break;
    }}
}}

// Register our TLS callback
#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback")

#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK _tls_callback = TlsCallback;
#else
// GCC/MinGW
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK _tls_callback = TlsCallback;
#endif

// TLS data section (required for TLS to work)
#ifdef _MSC_VER
#pragma data_seg(".tls")
#pragma data_seg()
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif
'''


class BuildScriptEmitter(CodeEmitter):
    """Generates build scripts for compiling the proxy DLL.

    Supports:
    - Static proxy (proxy_xxx.c)
    - Dynamic proxy with hooks (proxy_xxx_dynamic.c)
    - C++ exports (proxy_xxx_cpp.cpp)
    - TLS callbacks (tls_callback.c)
    - x64 MASM assembly (proxy_xxx_trampoline.asm)
    - Version resources (proxy_xxx.rc)
    """

    def __init__(self, include_dynamic: bool = True, include_asm: bool = True,
                 include_resources: bool = True, include_tls: bool = False,
                 include_cpp: bool = False):
        """Initialize build script emitter.

        Args:
            include_dynamic: Include dynamic proxy with hooks
            include_asm: Include ASM trampolines for x64
            include_resources: Include version resource
            include_tls: Include TLS callback handling
            include_cpp: Include C++ export wrapper
        """
        self.include_dynamic = include_dynamic
        self.include_asm = include_asm
        self.include_resources = include_resources
        self.include_tls = include_tls
        self.include_cpp = include_cpp

    def get_file_extensions(self) -> List[str]:
        return ['.bat', '.ps1']

    def emit(self, pe_info: PEInfo, output_dir: Path) -> List[Path]:
        dll_name = pe_info.path.stem.lower()
        created_files = []

        # Batch file
        bat_path = output_dir / f"build_{dll_name}.bat"
        bat_content = self._generate_batch(dll_name, pe_info)
        bat_path.write_text(bat_content, encoding="utf-8")
        created_files.append(bat_path)

        return created_files

    def _generate_batch(self, dll_name: str, pe_info: PEInfo) -> str:
        is_64bit = pe_info.is_64bit
        is_arm64 = getattr(pe_info, 'is_arm64', False)
        has_tls = getattr(pe_info, 'has_tls', False)
        has_cpp = any(exp.is_cpp_mangled for exp in pe_info.exports) if pe_info.exports else False

        if is_arm64:
            arch = "arm64"
            # 优先使用本地 ARM64 编译，如果在 ARM64 主机上
            # 否则使用 x64 到 ARM64 的交叉编译
            import platform
            if platform.machine().lower() in ('arm64', 'aarch64'):
                vcvars = "vcvarsarm64"      # 本地 ARM64 编译
            else:
                vcvars = "vcvarsamd64_arm64"  # x64 -> ARM64 交叉编译
        elif is_64bit:
            arch = "x64"
            vcvars = "vcvars64"
        else:
            arch = "x86"
            vcvars = "vcvars32"

        # Static and Dynamic are MUTUALLY EXCLUSIVE
        # Default to static proxy only; dynamic is selected via command line arg
        # Static: uses #pragma comment linker exports (simple, fast)
        # Dynamic: uses runtime loading with hooks (flexible, slower)
        static_src = f"proxy_{dll_name}.c"
        dynamic_src = f"proxy_{dll_name}_dynamic.c"

        extra_steps = []

        # ASM trampolines for x64
        if self.include_asm and is_64bit and not is_arm64:
            asm_file = f"proxy_{dll_name}_trampoline.asm"
            extra_steps.append(f'''
REM Assemble x64 trampolines
if exist "{asm_file}" (
    echo [INFO] Assembling {asm_file}...
    ml64 /nologo /c /Fo"proxy_{dll_name}_asm.obj" "{asm_file}"
    if errorlevel 1 (
        echo [WARNING] ASM compilation failed, continuing without trampolines...
    ) else (
        set OBJ_FILES=!OBJ_FILES! proxy_{dll_name}_asm.obj
    )
)''')

        # C++ exports
        if self.include_cpp or has_cpp:
            cpp_file = f"proxy_{dll_name}_cpp.cpp"
            extra_steps.append(f'''
REM Compile C++ exports
if exist "{cpp_file}" (
    echo [INFO] Compiling {cpp_file}...
    cl /nologo /c /O2 /EHsc "{cpp_file}" /Fo"proxy_{dll_name}_cpp.obj"
    if errorlevel 1 (
        echo [WARNING] C++ compilation failed, continuing...
    ) else (
        set OBJ_FILES=!OBJ_FILES! proxy_{dll_name}_cpp.obj
    )
)''')

        # TLS callbacks
        if self.include_tls or has_tls:
            tls_file = "tls_callback.c"
            extra_steps.append(f'''
REM Compile TLS callback handler
if exist "{tls_file}" (
    echo [INFO] Compiling {tls_file}...
    cl /nologo /c /O2 "{tls_file}" /Fo"tls_callback.obj"
    if errorlevel 1 (
        echo [WARNING] TLS compilation failed, continuing...
    ) else (
        set OBJ_FILES=!OBJ_FILES! tls_callback.obj
    )
)''')

        # Version resources
        rc_step = ""
        if self.include_resources:
            rc_file = f"proxy_{dll_name}.rc"
            rc_step = f'''
REM Compile version resources
if exist "{rc_file}" (
    echo [INFO] Compiling resources {rc_file}...
    rc /nologo /fo"proxy_{dll_name}.res" "{rc_file}"
    if errorlevel 1 (
        echo [WARNING] Resource compilation failed, continuing without version info...
    ) else (
        set RES_FILE=proxy_{dll_name}.res
    )
)'''

        extra_steps_str = "\n".join(extra_steps)

        # Build features description
        features = []
        if self.include_dynamic:
            features.append("Dynamic Hooks")
        else:
            features.append("Static Proxy")
        if self.include_asm and is_64bit and not is_arm64:
            features.append("ASM Trampolines")
        if self.include_tls or has_tls:
            features.append("TLS Callbacks")
        if self.include_resources:
            features.append("Resources")
        features_str = ", ".join(features)

        # Choose which source file to compile (mutually exclusive)
        if self.include_dynamic:
            main_src = dynamic_src
            use_def = True  # Dynamic proxy exports via DEF file (LNK2001 fix)
            def_file = f"proxy_{dll_name}_dynamic.def"
        else:
            main_src = static_src
            use_def = False  # Static proxy uses #pragma comment linker
            def_file = ""

        return f'''@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM Build script for {dll_name}.dll proxy
REM Target Architecture: {arch}
REM Mode: {"Dynamic (Hook support)" if self.include_dynamic else "Static (Fast forwarding)"}
REM Features: {features_str}
REM ============================================================================

set DLL_NAME={dll_name}
set OUT=%DLL_NAME%.dll
set OBJ_FILES=
set RES_FILE=

REM Check for Visual Studio compiler
where cl >nul 2>nul
if errorlevel 1 (
    echo [ERROR] cl.exe not found.
    echo Please run this script from a Visual Studio Developer Command Prompt.
    echo Or run: "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\{vcvars}.bat"
    exit /b 1
)

REM Copy original DLL if not present
if not exist "%DLL_NAME%_orig.dll" (
    if exist "%SystemRoot%\\System32\\%DLL_NAME%.dll" (
        echo [INFO] Copying original DLL from System32...
        copy "%SystemRoot%\\System32\\%DLL_NAME%.dll" "%DLL_NAME%_orig.dll" >nul
    ) else (
        echo [WARNING] Original DLL not found. Make sure %DLL_NAME%_orig.dll exists.
    )
)
{rc_step}
{extra_steps_str}

REM Compile main source file
echo [INFO] Compiling {main_src}...
if not exist "{main_src}" (
    echo [ERROR] Source file {main_src} not found.
    exit /b 1
)
cl /nologo /c /O2 "{main_src}"
if errorlevel 1 (
    echo [ERROR] Compilation failed.
    exit /b 1
)
set OBJ_FILES=!OBJ_FILES! {main_src.replace('.c', '.obj')}

REM Link
echo [INFO] Linking %OUT%...
set LINK_CMD=link /nologo /DLL /OUT:"%OUT%"
{f'set LINK_CMD=!LINK_CMD! /DEF:"{def_file}"' if use_def else ''}

if defined RES_FILE (
    set LINK_CMD=!LINK_CMD! !RES_FILE!
)

!LINK_CMD! !OBJ_FILES! kernel32.lib user32.lib

if errorlevel 1 (
    echo [ERROR] Linking failed.
    exit /b 1
)

REM Cleanup object files
echo [INFO] Cleaning up...
del /q *.obj 2>nul
del /q *.res 2>nul
del /q *.exp 2>nul
del /q *.lib 2>nul

echo.
echo [SUCCESS] Built %OUT%
echo.
echo To use:
echo   1. Rename original {dll_name}.dll to {dll_name}_orig.dll
echo   2. Place the generated {dll_name}.dll in the same directory
echo.
'''
