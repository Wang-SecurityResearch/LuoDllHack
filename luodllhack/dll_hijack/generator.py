# -*- coding: utf-8 -*-
"""
sys_dll/generator.py
Main proxy DLL generator interface.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional

from .models import PEInfo
from .interfaces import CodeEmitter
from .parser import PEParser
from .emitters import DefFileEmitter, CCodeEmitter, DynamicProxyEmitter, BuildScriptEmitter


class ProxyGenerator:
    """
    Main interface for generating DLL proxy files.
    Combines PE parsing, export extraction, and code emission.

    Supports two proxy modes:
    - Static (pragma-based): Fast, no runtime overhead, but no hook support
    - Dynamic (GetProcAddress): Supports function hooking and interception
    """

    def __init__(self,
                 parser: PEParser = None,
                 emitters: List[CodeEmitter] = None,
                 include_dynamic: bool = True,
                 validate: bool = True):
        """Initialize the proxy generator.

        Args:
            parser: PE parser to use. Defaults to PEParser with CompositeExtractor.
            emitters: List of code emitters. If None, uses default emitters.
            include_dynamic: Include dynamic proxy emitter (default: True)
            validate: Validate generated exports (default: True)
        """
        self._parser = parser or PEParser()
        self._validate = validate

        if emitters is not None:
            self._emitters = emitters
        else:
            # Static and Dynamic are mutually exclusive modes
            # Static: uses pragma comment linker (fast, no hooks)
            # Dynamic: uses GetProcAddress (slower, supports hooks)
            self._emitters = [
                DefFileEmitter(mode='forwarder'),  # Always generate forwarder DEF
            ]
            if include_dynamic:
                # Dynamic mode with hook support
                self._emitters.append(DefFileEmitter(mode='dynamic'))  # DEF for dynamic proxy
                self._emitters.append(DynamicProxyEmitter())
                self._emitters.append(BuildScriptEmitter(include_dynamic=True))
            else:
                # Static mode (default)
                self._emitters.append(CCodeEmitter())
                self._emitters.append(BuildScriptEmitter(include_dynamic=False))

    def generate(self, dll_path: Path, output_dir: Path = None) -> Dict[str, Any]:
        """
        Generate all proxy files for the given DLL.

        Args:
            dll_path: Path to the target DLL
            output_dir: Output directory (defaults to current directory)

        Returns:
            Dictionary containing generation results and metadata
        """
        output_dir = output_dir or Path.cwd()
        output_dir.mkdir(parents=True, exist_ok=True)

        result = {
            'success': False,
            'dll_path': str(dll_path),
            'output_dir': str(output_dir),
            'pe_info': None,
            'generated_files': [],
            'errors': []
        }

        try:
            # Parse PE file
            pe_info = self._parser.parse(dll_path)
            result['pe_info'] = {
                'name': pe_info.path.name,
                'arch': pe_info.arch_name,
                'exports_count': len(pe_info.exports),
                'image_base': hex(pe_info.image_base)
            }

            print(f"[+] Target: {dll_path}")
            print(f"    Architecture: {pe_info.arch_name}")
            print(f"    Image Base: {hex(pe_info.image_base)}")
            print(f"    Exports: {len(pe_info.exports)}")

            # Run all emitters
            for emitter in self._emitters:
                try:
                    files = emitter.emit(pe_info, output_dir)
                    for f in files:
                        result['generated_files'].append(str(f))
                        print(f"[+] Generated: {f}")
                except Exception as e:
                    error_msg = f"{emitter.__class__.__name__}: {e}"
                    result['errors'].append(error_msg)
                    print(f"[-] {error_msg}")

            result['success'] = len(result['errors']) == 0

            # Validate generated files
            if self._validate and result['success']:
                from .validator import validate_proxy
                validation_results = validate_proxy(pe_info, output_dir)
                result['validation'] = {}

                all_valid = True
                for filename, vr in validation_results.items():
                    result['validation'][filename] = {
                        'valid': vr.is_valid,
                        'original': vr.original_count,
                        'generated': vr.generated_count,
                        'missing': len(vr.missing_exports),
                        'warnings': vr.warnings
                    }
                    if vr.is_valid:
                        print(f"[OK] Validated: {filename}")
                    else:
                        print(f"[!] Validation issues in {filename}:")
                        print(f"    {vr.summary}")
                        all_valid = False

                if not all_valid:
                    result['warnings'] = result.get('warnings', [])
                    result['warnings'].append("Some generated files have validation issues")

        except Exception as e:
            result['errors'].append(str(e))
            print(f"[-] Error: {e}")

        return result

    def add_emitter(self, emitter: CodeEmitter):
        """Add a custom code emitter."""
        self._emitters.append(emitter)

    def get_supported_extensions(self) -> List[str]:
        """Get list of all file extensions that can be generated."""
        extensions = []
        for emitter in self._emitters:
            extensions.extend(emitter.get_file_extensions())
        return list(set(extensions))

    def generate_and_compile(
        self,
        dll_path: Path,
        output_dir: Path = None,
        compile_static: bool = True,
        compile_dynamic: bool = False,
        arch: str = None,
        prefer: str = None
    ) -> Dict[str, Any]:
        """Generate proxy files and compile to DLL.

        Args:
            dll_path: Path to the target DLL
            output_dir: Output directory (defaults to current directory)
            compile_static: Compile static proxy (default: True)
            compile_dynamic: Compile dynamic proxy (default: False)
            arch: Target architecture ('x86' or 'x64'), auto-detect if None
            prefer: Preferred compiler ('msvc' or 'mingw')

        Returns:
            Dictionary containing generation and compilation results
        """
        dll_path = Path(dll_path)

        # First generate the source files
        result = self.generate(dll_path, output_dir)

        if not result['success']:
            return result

        output_dir = Path(result['output_dir'])
        result['compiled'] = []

        # Import compiler
        from .compiler import AutoCompiler, Architecture, CompilerType

        # Set compiler preference
        compiler_pref = None
        if prefer:
            compiler_pref = CompilerType.MINGW if prefer.lower() == 'mingw' else CompilerType.MSVC

        compiler = AutoCompiler(preferred=compiler_pref)

        if not compiler.is_available():
            result['warnings'] = result.get('warnings', [])
            result['warnings'].append("没有可用的编译器，请安装 MSVC 或 MinGW")
            print("[!] 没有可用的编译器")
            return result

        print(f"\n[*] 可用编译器: {', '.join(compiler.get_available_compilers())}")

        # Determine architecture: user override > PE detection
        if arch:
            target_arch = Architecture.X64 if arch.lower() == 'x64' else Architecture.X86
        else:
            target_arch = Architecture.X64 if result['pe_info']['arch'] == 'x64' else Architecture.X86

        dll_name = Path(dll_path).stem.lower()

        # Compile static proxy
        if compile_static:
            static_src = output_dir / f"proxy_{dll_name}.c"
            def_file = output_dir / f"proxy_{dll_name}.def"

            if static_src.exists():
                print(f"\n[*] Compiling static proxy: {static_src.name}")
                compile_result = compiler.compile(
                    source_path=static_src,
                    output_dir=output_dir,
                    arch=arch,
                    def_path=def_file if def_file.exists() else None,
                    output_name=f"{dll_name}.dll"
                )

                result['compiled'].append({
                    'type': 'static',
                    'success': compile_result.success,
                    'output': str(compile_result.output_path) if compile_result.output_path else None,
                    'compiler': compile_result.compiler,
                    'error': compile_result.stderr if not compile_result.success else None
                })

                if compile_result.success:
                    print(f"[OK] {compile_result.summary}")
                else:
                    print(f"[FAIL] {compile_result.summary}")

        # Compile dynamic proxy
        if compile_dynamic:
            dynamic_src = output_dir / f"proxy_{dll_name}_dynamic.c"
            dynamic_def = output_dir / f"proxy_{dll_name}_dynamic.def"

            if dynamic_src.exists():
                print(f"\n[*] Compiling dynamic proxy: {dynamic_src.name}")
                compile_result = compiler.compile(
                    source_path=dynamic_src,
                    output_dir=output_dir,
                    arch=arch,
                    def_path=dynamic_def if dynamic_def.exists() else None,
                    output_name=f"{dll_name}_hook.dll"  # 动态代理加 _hook 后缀区分
                )

                result['compiled'].append({
                    'type': 'dynamic',
                    'success': compile_result.success,
                    'output': str(compile_result.output_path) if compile_result.output_path else None,
                    'compiler': compile_result.compiler,
                    'error': compile_result.stderr if not compile_result.success else None
                })

                if compile_result.success:
                    print(f"[OK] {compile_result.summary}")
                else:
                    print(f"[FAIL] {compile_result.summary}")

        return result

    @staticmethod
    def create_static_only() -> 'ProxyGenerator':
        """Create generator with only static proxy (no dynamic, faster)."""
        return ProxyGenerator(include_dynamic=False)

    @staticmethod
    def create_dynamic_only() -> 'ProxyGenerator':
        """Create generator with only dynamic proxy (for hooking)."""
        return ProxyGenerator(emitters=[
            DefFileEmitter(mode='dynamic'),  # DEF file for exports
            DynamicProxyEmitter(),
            BuildScriptEmitter(include_dynamic=True)
        ])
