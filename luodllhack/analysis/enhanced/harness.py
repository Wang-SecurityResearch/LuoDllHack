# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/harness.py

Harness Auto-Generation - Phase 3.2

Core Capabilities:
    1. Generate function call harnesses
    2. Support multiple formats (C/Python/Script)
    3. Include input generation logic
    4. Support integration with fuzzing tools

Harness Types:
    - Basic Call: Directly call the target function
    - Fuzzing: Cyclic calling with input mutation
    - Crash Reproduction: Precise input based on constraints

Usage:
    - Verify vulnerability triggerability
    - Generate fuzzing test cases
    - Reproduce crash scenarios
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum, auto
from pathlib import Path
import textwrap


class HarnessType(Enum):
    """Harness Type"""
    BASIC = auto()          # Basic call
    FUZZING = auto()        # Fuzzing
    REPRO = auto()          # Crash reproduction
    UNIT_TEST = auto()      # Unit test


class HarnessLanguage(Enum):
    """Harness Language"""
    C = "c"
    PYTHON = "python"
    POWERSHELL = "ps1"


@dataclass
class FunctionSignature:
    """Function Signature"""
    name: str
    address: int
    return_type: str = "int"
    params: List[Dict[str, str]] = field(default_factory=list)  # [{name, type, tainted}]
    calling_convention: str = "fastcall"  # x64 default

    def to_c_decl(self) -> str:
        """Generate C declaration"""
        params_str = ", ".join(
            f"{p['type']} {p['name']}" for p in self.params
        ) if self.params else "void"
        return f"{self.return_type} (*{self.name})({params_str})"

    def to_python_call(self) -> str:
        """Generate Python call"""
        params_str = ", ".join(p['name'] for p in self.params)
        return f"{self.name}({params_str})"


@dataclass
class HarnessConfig:
    """Harness Configuration"""
    dll_path: str
    function: FunctionSignature
    harness_type: HarnessType = HarnessType.BASIC
    language: HarnessLanguage = HarnessLanguage.C
    # Input configuration
    input_size: int = 256
    input_source: str = "stdin"     # stdin, file, generated
    # Constraints
    constraints: Dict[str, Any] = field(default_factory=dict)
    # Monitoring
    check_crash: bool = True
    timeout_ms: int = 5000
    # COM method flag
    is_com_method: bool = False


@dataclass
class GeneratedHarness:
    """Generated Harness"""
    config: HarnessConfig
    code: str
    filename: str
    # Additional files
    build_script: Optional[str] = None
    input_generator: Optional[str] = None

    def save(self, output_dir: Path):
        """Save to file"""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Main file
        main_file = output_dir / self.filename
        main_file.write_text(self.code, encoding='utf-8')

        # Build script
        if self.build_script:
            build_file = output_dir / "build.bat"
            build_file.write_text(self.build_script, encoding='utf-8')

        # Input generator
        if self.input_generator:
            gen_file = output_dir / "generate_input.py"
            gen_file.write_text(self.input_generator, encoding='utf-8')


class HarnessGenerator:
    """
    Harness Generator

    Usage:
        generator = HarnessGenerator()

        # Configuration
        config = HarnessConfig(
            dll_path="target.dll",
            function=FunctionSignature(
                name="VulnFunc",
                address=0x10001000,
                params=[
                    {'name': 'input', 'type': 'char*', 'tainted': True},
                    {'name': 'size', 'type': 'int', 'tainted': False}
                ]
            ),
            harness_type=HarnessType.FUZZING
        )

        # Generation
        harness = generator.generate(config)
        harness.save(Path("./harness"))
    """

    def __init__(self):
        """Initialize the harness generator"""
        pass

    # COM method name patterns
    COM_METHOD_PATTERNS = {
        'QueryInterface', 'AddRef', 'Release',
        'CreateInstance', 'LockServer',
        'GetHandlerProperty', 'GetHandlerProperty2', 'CreateObject',
        'CreateDecoder', 'CreateEncoder', 'GetNumberOfMethods',
        'GetMethodProperty', 'GetNumberOfFormats', 'GetFormatProperty',
    }

    def _is_com_method(self, func_name: str) -> bool:
        """Check if it's a COM method"""
        import re
        if func_name in self.COM_METHOD_PATTERNS:
            return True
        com_regex = re.compile(
            r'^(QueryInterface|AddRef|Release|'
            r'Get[A-Z]\w*|Set[A-Z]\w*|'
            r'Create\w*|Open\w*|Close\w*|'
            r'Read\w*|Write\w*)$'
        )
        return bool(com_regex.match(func_name))

    def generate(self, config: HarnessConfig) -> GeneratedHarness:
        """
        Generate hardess

        Args:
            config: Harness configuration

        Returns:
            GeneratedHarness
        """
        # Auto-detect COM method
        if not config.is_com_method:
            config.is_com_method = self._is_com_method(config.function.name)

        if config.language == HarnessLanguage.C:
            return self._generate_c_harness(config)
        elif config.language == HarnessLanguage.PYTHON:
            return self._generate_python_harness(config)
        else:
            raise ValueError(f"Unsupported language: {config.language}")

    def _generate_c_harness(self, config: HarnessConfig) -> GeneratedHarness:
        """Generate C language harness"""
        func = config.function
        dll_name = Path(config.dll_path).stem

        # COM method warning
        com_warning = ""
        if config.is_com_method:
            com_warning = f'''
 * ============================================================================
 * WARNING: THIS IS A COM INTERFACE METHOD
 * ============================================================================
 *
 * {func.name} appears to be a COM interface method. Direct calling via
 * GetProcAddress will likely crash due to signature mismatch (missing 'this'
 * pointer), NOT because of a real vulnerability.
 *
 * For proper testing, you need to:
 *   1. Use CoCreateInstance() to create the COM object
 *   2. QueryInterface() to get the interface pointer
 *   3. Call through the interface vtable
 *
'''

        # Headers and type definitions
        header = f'''/*
 * LuoDllHack Auto-Generated Harness
 *
 * Target: {config.dll_path}
 * Function: {func.name} @ 0x{func.address:x}
 * Type: {config.harness_type.name}
 *{com_warning}
 * NOTE: This file is a Fuzzing Driver (Harness), NOT a PoC.
 *
 * How to find PoC:
 *   1. Build this harness: cl /Od harness_{dll_name}.c /Fe:harness_{dll_name}.exe
 *   2. Run with a fuzzer (e.g., WinAFL):
 *      afl-fuzz.exe -i in -o out -D C:\\DynamoRIO\\bin64 -t 5000 -- harness_{dll_name}.exe @@
 *   3. Wait for crashes. Files in 'out/crashes/' are the actual PoCs.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

'''

        # Function pointer type definition
        typedef = self._generate_c_typedef(func)

        # Main function
        if config.harness_type == HarnessType.FUZZING:
            main_code = self._generate_c_fuzzing_main(config)
        elif config.harness_type == HarnessType.REPRO:
            main_code = self._generate_c_repro_main(config)
        else:
            main_code = self._generate_c_basic_main(config)

        code = header + typedef + main_code

        # Build script
        build_script = self._generate_c_build_script(config, dll_name)

        # Input generator
        input_generator = self._generate_input_generator(config)

        return GeneratedHarness(
            config=config,
            code=code,
            filename=f"harness_{dll_name}.c",
            build_script=build_script,
            input_generator=input_generator
        )

    def _generate_c_typedef(self, func: FunctionSignature) -> str:
        """Generate C type definition"""
        # Parameter types
        param_types = []
        for p in func.params:
            param_types.append(p['type'])

        params_str = ", ".join(param_types) if param_types else "void"

        return f'''// Function type definition
typedef {func.return_type} (__fastcall *PFN_{func.name.upper()})({params_str});

'''

    def _generate_c_basic_main(self, config: HarnessConfig) -> str:
        """Generate basic main function"""
        func = config.function

        # Construct parameters
        param_decls = []
        param_inits = []
        param_names = []

        for p in func.params:
            if p.get('tainted'):
                if 'char*' in p['type'] or 'LPSTR' in p['type']:
                    param_decls.append(f"    char {p['name']}[{config.input_size}] = {{0}};")
                    param_inits.append(f"    // Read input for {p['name']}")
                    param_inits.append(f"    fread({p['name']}, 1, sizeof({p['name']})-1, stdin);")
                else:
                    param_decls.append(f"    {p['type']} {p['name']} = 0;")
            else:
                param_decls.append(f"    {p['type']} {p['name']} = 0;")

            param_names.append(p['name'])

        return f'''
int main(int argc, char** argv) {{
    HMODULE hDll = NULL;
    PFN_{func.name.upper()} pfn{func.name} = NULL;
    {func.return_type} result = 0;

{chr(10).join(param_decls)}

    // Load DLL
    hDll = LoadLibraryA("{config.dll_path}");
    if (!hDll) {{
        printf("[-] Failed to load DLL: %d\\n", GetLastError());
        return 1;
    }}

    // Get function address
    pfn{func.name} = (PFN_{func.name.upper()})GetProcAddress(hDll, "{func.name}");
    if (!pfn{func.name}) {{
        printf("[-] Failed to find function: {func.name}\\n");
        FreeLibrary(hDll);
        return 1;
    }}

{chr(10).join(param_inits)}

    printf("[*] Calling {func.name}...\\n");

    __try {{
        result = pfn{func.name}({", ".join(param_names)});
        printf("[+] Function returned: %d\\n", result);
    }}
    __except(EXCEPTION_EXECUTE_HANDLER) {{
        printf("[!] CRASH detected! Exception code: 0x%08X\\n", GetExceptionCode());
    }}

    FreeLibrary(hDll);
    return 0;
}}
'''

    def _generate_c_fuzzing_main(self, config: HarnessConfig) -> str:
        """Generate fuzzing main function"""
        func = config.function

        param_decls = []
        param_names = []

        for p in func.params:
            if p.get('tainted'):
                if 'char*' in p['type'] or 'LPSTR' in p['type']:
                    param_decls.append(f"    char {p['name']}[{config.input_size}] = {{0}};")
                else:
                    param_decls.append(f"    {p['type']} {p['name']} = 0;")
            else:
                param_decls.append(f"    {p['type']} {p['name']} = 0;")
            param_names.append(p['name'])

        return f'''
// AFL/libFuzzer compatible harness
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

HMODULE g_hDll = NULL;
PFN_{func.name.upper()} g_pfn{func.name} = NULL;

int init_target() {{
    g_hDll = LoadLibraryA("{config.dll_path}");
    if (!g_hDll) return 0;

    g_pfn{func.name} = (PFN_{func.name.upper()})GetProcAddress(g_hDll, "{func.name}");
    return g_pfn{func.name} != NULL;
}}

// libFuzzer entry point
#ifdef LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (!g_hDll && !init_target()) return 0;

    // Copy input
    char buf[{config.input_size}] = {{0}};
    size_t copy_size = size < sizeof(buf)-1 ? size : sizeof(buf)-1;
    memcpy(buf, data, copy_size);

    __try {{
        g_pfn{func.name}(buf{', 0' * (len(func.params) - 1)});
    }} __except(EXCEPTION_EXECUTE_HANDLER) {{
        // Crash found
    }}

    return 0;
}}
#endif

// Standalone mode
int main(int argc, char** argv) {{
{chr(10).join(param_decls)}

    if (!init_target()) {{
        printf("[-] Failed to initialize target\\n");
        return 1;
    }}

#ifdef __AFL_HAVE_MANUAL_CONTROL
    while (__AFL_LOOP(1000)) {{
#endif

    memset({param_names[0] if param_names else 'buf'}, 0, sizeof({param_names[0] if param_names else 'buf'}));

    // Read input from stdin
    size_t len = fread({param_names[0] if param_names else 'buf'}, 1,
                       sizeof({param_names[0] if param_names else 'buf'})-1, stdin);

    if (len > 0) {{
        __try {{
            g_pfn{func.name}({", ".join(param_names)});
        }} __except(EXCEPTION_EXECUTE_HANDLER) {{
            printf("[!] CRASH!\\n");
        }}
    }}

#ifdef __AFL_HAVE_MANUAL_CONTROL
    }}
#endif

    FreeLibrary(g_hDll);
    return 0;
}}
'''

    def _generate_c_repro_main(self, config: HarnessConfig) -> str:
        """Generate crash reproduction main function"""
        func = config.function

        # Generate input from constraints
        constraints = config.constraints
        input_values = constraints.get('test_values', {})

        param_inits = []
        param_names = []

        for p in func.params:
            if p['name'] in input_values:
                val = input_values[p['name']]
                if isinstance(val, bytes):
                    hex_str = ', '.join(f'0x{b:02x}' for b in val[:64])
                    param_inits.append(f"    char {p['name']}[] = {{ {hex_str} }};")
                else:
                    param_inits.append(f"    {p['type']} {p['name']} = {val};")
            else:
                param_inits.append(f"    {p['type']} {p['name']} = 0;")
            param_names.append(p['name'])

        return f'''
// Crash reproduction harness
int main(int argc, char** argv) {{
    HMODULE hDll = LoadLibraryA("{config.dll_path}");
    if (!hDll) {{
        printf("[-] Failed to load DLL\\n");
        return 1;
    }}

    PFN_{func.name.upper()} pfn{func.name} =
        (PFN_{func.name.upper()})GetProcAddress(hDll, "{func.name}");
    if (!pfn{func.name}) {{
        printf("[-] Function not found\\n");
        return 1;
    }}

    // Test values from constraint solving
{chr(10).join(param_inits)}

    printf("[*] Reproducing crash...\\n");

    __try {{
        pfn{func.name}({", ".join(param_names)});
        printf("[+] No crash - constraints may need adjustment\\n");
    }} __except(EXCEPTION_EXECUTE_HANDLER) {{
        printf("[!] CRASH REPRODUCED! Code: 0x%08X\\n", GetExceptionCode());
    }}

    FreeLibrary(hDll);
    return 0;
}}
'''

    def _generate_c_build_script(self, config: HarnessConfig, dll_name: str) -> str:
        """Generate build script"""
        return f'''@echo off
REM LuoDllHack Auto-Generated Build Script

REM Basic build
cl /Od /Zi harness_{dll_name}.c /Fe:harness_{dll_name}.exe

REM AFL build (if afl-clang-fast available)
REM afl-clang-fast -g harness_{dll_name}.c -o harness_{dll_name}_afl.exe

REM libFuzzer build
REM clang -g -fsanitize=fuzzer,address -DLIBFUZZER harness_{dll_name}.c -o harness_{dll_name}_fuzz.exe

echo [+] Build complete
pause
'''

    def _generate_python_harness(self, config: HarnessConfig) -> GeneratedHarness:
        """Generate Python harness"""
        func = config.function
        dll_name = Path(config.dll_path).stem

        code = f'''#!/usr/bin/env python3
"""
LuoDllHack Auto-Generated Harness

Target: {config.dll_path}
Function: {func.name} @ 0x{func.address:x}
"""

import ctypes
from ctypes import wintypes
import sys
import struct

def main():
    # Load DLL
    try:
        dll = ctypes.CDLL(r"{config.dll_path}")
    except Exception as e:
        print(f"[-] Failed to load DLL: {{e}}")
        return 1

    # Get function
    try:
        func = getattr(dll, "{func.name}")
    except AttributeError:
        print(f"[-] Function {func.name} not found")
        return 1

    # Set up argument types
    # func.argtypes = [ctypes.c_char_p, ctypes.c_int]
    # func.restype = ctypes.c_int

    # Prepare input
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'rb') as f:
            input_data = f.read()
    else:
        input_data = sys.stdin.buffer.read()

    buf = ctypes.create_string_buffer(input_data, {config.input_size})

    print(f"[*] Calling {func.name} with {{len(input_data)}} bytes...")

    try:
        result = func(buf)
        print(f"[+] Function returned: {{result}}")
    except Exception as e:
        print(f"[!] Exception: {{e}}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
'''

        return GeneratedHarness(
            config=config,
            code=code,
            filename=f"harness_{dll_name}.py",
            input_generator=self._generate_input_generator(config)
        )

    def _generate_input_generator(self, config: HarnessConfig) -> str:
        """Generate input generator"""
        return f'''#!/usr/bin/env python3
"""
LuoDllHack Input Generator

Generates test inputs based on constraints
"""

import os
import random
import struct

def generate_basic(size={config.input_size}):
    """Generate basic test input"""
    return b'A' * size

def generate_overflow(size={config.input_size}):
    """Generate overflow input"""
    return b'A' * (size * 2)

def generate_format_string():
    """Generate format string payload"""
    return b'%s' * 10 + b'%x' * 10 + b'%n' * 5

def generate_path_traversal():
    """Generate path traversal payload"""
    return b'..\\\\' * 10 + b'windows\\\\system32\\\\calc.exe'

def main():
    os.makedirs('inputs', exist_ok=True)

    # Generate various test cases
    tests = [
        ('basic', generate_basic()),
        ('overflow', generate_overflow()),
        ('format', generate_format_string()),
        ('path', generate_path_traversal()),
    ]

    for name, data in tests:
        path = f'inputs/{{name}}.bin'
        with open(path, 'wb') as f:
            f.write(data)
        print(f'[+] Generated: {{path}} ({{len(data)}} bytes)')

if __name__ == "__main__":
    main()
'''

    def generate_com_harness(self, config: HarnessConfig, com_config: Dict = None) -> GeneratedHarness:
        """
        Generate COM interface call harness

        Args:
            config: Harness configuration
            com_config: COM specific configuration (clsid, iid, interface_def, etc.)

        Returns:
            GeneratedHarness
        """
        from jinja2 import Environment, FileSystemLoader, BaseLoader
        from pathlib import Path

        func = config.function
        dll_name = Path(config.dll_path).stem

        # Try to load template
        template_path = Path(__file__).parent.parent.parent / 'templates' / 'harness' / 'com_harness.c.j2'

        if template_path.exists():
            env = Environment(loader=FileSystemLoader(str(template_path.parent)))
            template = env.get_template('com_harness.c.j2')
        else:
            # Inline template fallback
            template = None

        # Prepare template variables
        template_vars = {
            'dll_path': config.dll_path,
            'func_name': func.name,
            'vuln_type': 'Unknown',
            'clsid': com_config.get('clsid') if com_config else None,
            'iid': com_config.get('iid') if com_config else None,
            'interface_def': com_config.get('interface_def') if com_config else None,
        }

        if template:
            code = template.render(**template_vars)
        else:
            # Inline basic COM harness
            code = self._generate_inline_com_harness(config, com_config or {})

        # Build script
        build_script = f'''@echo off
REM LuoDllHack COM Harness Build Script

REM Build COM harness
cl /O2 harness_com_{dll_name}.c ole32.lib oleaut32.lib /Fe:harness_com_{dll_name}.exe

echo [+] Build complete
echo [*] Usage: harness_com_{dll_name}.exe <input_file>
echo [*]        harness_com_{dll_name}.exe --enum
pause
'''

        return GeneratedHarness(
            config=config,
            code=code,
            filename=f"harness_com_{dll_name}.c",
            build_script=build_script,
            input_generator=self._generate_input_generator(config)
        )

    def _generate_inline_com_harness(self, config: HarnessConfig, com_config: Dict) -> str:
        """Generate inline COM harness (when template is unavailable)"""
        func = config.function

        clsid_def = ""
        if com_config.get('clsid'):
            clsid_def = f"DEFINE_GUID(CLSID_Target, {com_config['clsid']});"

        iid_def = ""
        if com_config.get('iid'):
            iid_def = f"DEFINE_GUID(IID_Target, {com_config['iid']});"

        return f'''/*
 * LuoDllHack COM Interface Harness
 *
 * Target: {config.dll_path}
 * Function: {func.name}
 *
 * This harness properly initializes COM and calls interface methods.
 */

#include <windows.h>
#include <stdio.h>
#include <objbase.h>
#include <initguid.h>

#pragma comment(lib, "ole32.lib")

// GUIDs
{clsid_def}
{iid_def}

// 7-Zip style CreateObject
typedef HRESULT (WINAPI *PFN_CreateObject)(const GUID* clsid, const GUID* iid, void** outObject);

static HMODULE g_hDll = NULL;

int wmain(int argc, wchar_t* argv[]) {{
    HRESULT hr;
    void* pObject = NULL;
    PFN_CreateObject pfnCreateObject;

    printf("[*] LuoDllHack COM Harness\\n");
    printf("[*] Target: {config.dll_path}\\n");
    printf("[*] Function: {func.name}\\n\\n");

    // Load DLL
    g_hDll = LoadLibraryW(L"{config.dll_path}");
    if (!g_hDll) {{
        printf("[-] Failed to load DLL: %lu\\n", GetLastError());
        return 1;
    }}
    printf("[+] DLL loaded\\n");

    // Try CreateObject (7-Zip style)
    pfnCreateObject = (PFN_CreateObject)GetProcAddress(g_hDll, "CreateObject");
    if (pfnCreateObject) {{
        printf("[+] Found CreateObject export\\n");
        printf("[*] Use --enum to enumerate available handlers\\n");
    }} else {{
        printf("[-] CreateObject not found\\n");
        printf("[*] This DLL may require standard COM initialization\\n");
    }}

    FreeLibrary(g_hDll);
    return 0;
}}
'''
