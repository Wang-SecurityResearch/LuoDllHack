# -*- coding: utf-8 -*-
"""
sys_dll/compiler.py
Automated DLL compilation with MSVC and MinGW support.
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass
from abc import ABC, abstractmethod
from enum import Enum, auto


class CompilerType(Enum):
    """Supported compiler types."""
    MSVC = auto()
    MINGW = auto()
    CLANG = auto()


class Architecture(Enum):
    """Target architectures."""
    X86 = "x86"
    X64 = "x64"
    ARM64 = "arm64"


@dataclass
class CompileResult:
    """Result of compilation."""
    success: bool
    output_path: Optional[Path]
    compiler: str
    architecture: str
    stdout: str
    stderr: str
    command: str

    @property
    def summary(self) -> str:
        if self.success:
            return f"Compiled: {self.output_path} ({self.compiler}, {self.architecture})"
        return f"Failed: {self.compiler} ({self.architecture})\n{self.stderr[:500]}"


class Compiler(ABC):
    """Abstract base class for compilers."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this compiler is available."""
        pass

    @abstractmethod
    def compile(
        self,
        source_path: Path,
        output_path: Path,
        arch: Architecture,
        def_path: Optional[Path] = None,
        extra_flags: List[str] = None
    ) -> CompileResult:
        """Compile source to DLL."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Get compiler name."""
        pass


class MSVCCompiler(Compiler):
    """Microsoft Visual C++ Compiler."""

    # VS installation paths to search
    VS_PATHS = [
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional",
        r"C:\Program Files\Microsoft Visual Studio\2022\Community",
        r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools",
    ]

    def __init__(self):
        self._vs_path = self._find_vs_installation()
        self._vcvars_cache: Dict[Architecture, Dict[str, str]] = {}

    def _find_vs_installation(self) -> Optional[Path]:
        """Find Visual Studio installation."""
        for path in self.VS_PATHS:
            vs_path = Path(path)
            vcvars = vs_path / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
            if vcvars.exists():
                return vs_path
        return None

    def is_available(self) -> bool:
        return self._vs_path is not None

    def get_name(self) -> str:
        return "MSVC"

    def _get_vcvars_env(self, arch: Architecture) -> Dict[str, str]:
        """Get environment variables after running vcvars."""
        if arch in self._vcvars_cache:
            return self._vcvars_cache[arch]

        if not self._vs_path:
            return {}

        # 选择正确的 vcvars 脚本
        import platform
        host_arch = platform.machine().lower()

        if arch == Architecture.ARM64:
            if host_arch in ('arm64', 'aarch64'):
                vcvars_script = "vcvarsarm64.bat"  # 本地 ARM64 编译
            else:
                vcvars_script = "vcvarsamd64_arm64.bat"  # x64 -> ARM64 交叉编译
        elif arch == Architecture.X64:
            vcvars_script = "vcvars64.bat"
        else:
            vcvars_script = "vcvars32.bat"

        vcvars_path = self._vs_path / "VC" / "Auxiliary" / "Build" / vcvars_script

        if not vcvars_path.exists():
            # Try vcvarsall.bat with arch parameter
            vcvarsall = self._vs_path / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
            if vcvarsall.exists():
                if arch == Architecture.ARM64:
                    if host_arch in ('arm64', 'aarch64'):
                        arch_param = "arm64"
                    else:
                        arch_param = "amd64_arm64"  # 交叉编译
                elif arch == Architecture.X64:
                    arch_param = "x64"
                else:
                    arch_param = "x86"
                cmd = f'"{vcvarsall}" {arch_param} && set'
            else:
                return {}
        else:
            cmd = f'"{vcvars_path}" && set'

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            env = {}
            for line in result.stdout.splitlines():
                if '=' in line:
                    key, _, value = line.partition('=')
                    env[key] = value

            self._vcvars_cache[arch] = env
            return env

        except Exception:
            return {}

    def compile(
        self,
        source_path: Path,
        output_path: Path,
        arch: Architecture,
        def_path: Optional[Path] = None,
        extra_flags: List[str] = None
    ) -> CompileResult:
        """Compile using MSVC cl.exe."""
        if not self.is_available():
            return CompileResult(
                success=False,
                output_path=None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout="",
                stderr="MSVC not found",
                command=""
            )

        env = self._get_vcvars_env(arch)
        if not env:
            return CompileResult(
                success=False,
                output_path=None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout="",
                stderr="Failed to initialize MSVC environment",
                command=""
            )

        # Build command
        cmd_parts = [
            "cl.exe",
            "/nologo",
            "/LD",           # Create DLL
            "/O2",           # Optimize for speed
            "/W3",           # Warning level 3
            "/MD",           # Multi-threaded DLL runtime
            str(source_path),
            f"/Fe:{output_path}",
        ]

        # Add .def file if provided
        if def_path and def_path.exists():
            cmd_parts.append(f"/link")
            cmd_parts.append(f"/DEF:{def_path}")

        # Add extra flags
        if extra_flags:
            cmd_parts.extend(extra_flags)

        cmd = " ".join(cmd_parts)

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                env=env,
                cwd=source_path.parent,
                timeout=120
            )

            success = result.returncode == 0 and output_path.exists()

            return CompileResult(
                success=success,
                output_path=output_path if success else None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout=result.stdout,
                stderr=result.stderr,
                command=cmd
            )

        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                output_path=None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout="",
                stderr="Compilation timeout (120s)",
                command=cmd
            )
        except Exception as e:
            return CompileResult(
                success=False,
                output_path=None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout="",
                stderr=str(e),
                command=cmd
            )


class MinGWCompiler(Compiler):
    """MinGW-w64 GCC Compiler."""

    def __init__(self):
        self._gcc_path = self._find_mingw()

    def _find_mingw(self) -> Optional[str]:
        """Find MinGW gcc."""
        # Check PATH
        gcc = shutil.which("gcc")
        if gcc:
            return gcc

        # Check common locations
        mingw_paths = [
            r"C:\mingw64\bin\gcc.exe",
            r"C:\mingw-w64\mingw64\bin\gcc.exe",
            r"C:\msys64\mingw64\bin\gcc.exe",
            r"C:\msys64\ucrt64\bin\gcc.exe",
            r"C:\Program Files\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin\gcc.exe",
        ]

        for path in mingw_paths:
            if Path(path).exists():
                return path

        return None

    def is_available(self) -> bool:
        return self._gcc_path is not None

    def get_name(self) -> str:
        return "MinGW"

    def compile(
        self,
        source_path: Path,
        output_path: Path,
        arch: Architecture,
        def_path: Optional[Path] = None,
        extra_flags: List[str] = None
    ) -> CompileResult:
        """Compile using MinGW gcc."""
        if not self.is_available():
            return CompileResult(
                success=False,
                output_path=None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout="",
                stderr="MinGW not found",
                command=""
            )

        # Build command
        cmd_parts = [
            self._gcc_path,
            "-shared",
            "-o", str(output_path),
            str(source_path),
            "-O2",
            "-Wall",
        ]

        # Architecture flags
        if arch == Architecture.X64:
            cmd_parts.extend(["-m64"])
        else:
            cmd_parts.extend(["-m32"])

        # Windows-specific flags
        cmd_parts.extend([
            "-lkernel32",
            "-luser32",
        ])

        # Add .def file if provided
        if def_path and def_path.exists():
            cmd_parts.append(f"-Wl,--output-def,{def_path}")

        # Add extra flags
        if extra_flags:
            cmd_parts.extend(extra_flags)

        cmd = " ".join(cmd_parts)

        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                cwd=source_path.parent,
                timeout=120
            )

            success = result.returncode == 0 and output_path.exists()

            return CompileResult(
                success=success,
                output_path=output_path if success else None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout=result.stdout,
                stderr=result.stderr,
                command=cmd
            )

        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                output_path=None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout="",
                stderr="Compilation timeout (120s)",
                command=cmd
            )
        except Exception as e:
            return CompileResult(
                success=False,
                output_path=None,
                compiler=self.get_name(),
                architecture=arch.value,
                stdout="",
                stderr=str(e),
                command=cmd
            )


class AutoCompiler:
    """Automatically selects and uses available compiler."""

    def __init__(self, preferred: CompilerType = None):
        """Initialize with optional preferred compiler.

        Args:
            preferred: Preferred compiler type (MSVC or MINGW)
        """
        self._compilers: List[Compiler] = []
        self._preferred = preferred

        # Initialize compilers in preference order
        msvc = MSVCCompiler()
        mingw = MinGWCompiler()

        if preferred == CompilerType.MINGW:
            if mingw.is_available():
                self._compilers.append(mingw)
            if msvc.is_available():
                self._compilers.append(msvc)
        else:
            # Default: prefer MSVC
            if msvc.is_available():
                self._compilers.append(msvc)
            if mingw.is_available():
                self._compilers.append(mingw)

    def is_available(self) -> bool:
        """Check if any compiler is available."""
        return len(self._compilers) > 0

    def get_available_compilers(self) -> List[str]:
        """Get list of available compiler names."""
        return [c.get_name() for c in self._compilers]

    def compile(
        self,
        source_path: Path,
        output_dir: Path,
        arch: Architecture = None,
        def_path: Optional[Path] = None,
        output_name: str = None
    ) -> CompileResult:
        """Compile source file to DLL.

        Args:
            source_path: Path to C source file
            output_dir: Output directory for DLL
            arch: Target architecture (auto-detect if None)
            def_path: Optional .def file for exports
            output_name: Output DLL name (derived from source if None)

        Returns:
            CompileResult with compilation details
        """
        if not self._compilers:
            return CompileResult(
                success=False,
                output_path=None,
                compiler="None",
                architecture="unknown",
                stdout="",
                stderr="No compiler available. Install MSVC or MinGW.",
                command=""
            )

        # Auto-detect architecture from source if not specified
        if arch is None:
            arch = self._detect_architecture(source_path)
        elif isinstance(arch, str):
            # Convert string to Architecture enum
            arch_str = arch.lower()
            if arch_str in ('x64', 'amd64', 'x86_64'):
                arch = Architecture.X64
            elif arch_str in ('x86', 'i386', 'win32'):
                arch = Architecture.X86
            elif arch_str in ('arm64', 'aarch64'):
                arch = Architecture.ARM64
            else:
                arch = Architecture.X64  # Default

        # Determine output name
        if output_name is None:
            # proxy_version.c -> version.dll
            stem = source_path.stem
            if stem.startswith("proxy_"):
                stem = stem[6:]  # Remove "proxy_" prefix
            if stem.endswith("_dynamic"):
                stem = stem[:-8]  # Remove "_dynamic" suffix
            output_name = f"{stem}.dll"

        output_path = output_dir / output_name

        # Try each compiler until one succeeds
        last_result = None
        for compiler in self._compilers:
            print(f"[*] Trying {compiler.get_name()} ({arch.value})...")

            result = compiler.compile(
                source_path=source_path,
                output_path=output_path,
                arch=arch,
                def_path=def_path
            )

            if result.success:
                return result

            last_result = result
            print(f"    {compiler.get_name()} failed: {result.stderr[:100]}")

        return last_result or CompileResult(
            success=False,
            output_path=None,
            compiler="None",
            architecture=arch.value,
            stdout="",
            stderr="All compilers failed",
            command=""
        )

    def _detect_architecture(self, source_path: Path) -> Architecture:
        """Detect target architecture from source file."""
        try:
            content = source_path.read_text(encoding='utf-8', errors='ignore')

            # Look for architecture hints in the source
            if 'x64' in content.lower() or 'win64' in content.lower():
                return Architecture.X64
            if 'x86' in content.lower() or 'win32' in content.lower():
                return Architecture.X86

            # Check for 64-bit specific code patterns
            if '__declspec(naked)' in content:
                # naked functions with __asm are typically x86
                return Architecture.X86

        except Exception:
            pass

        # Default to x64 for modern systems
        return Architecture.X64

    def compile_all(
        self,
        output_dir: Path,
        arch: Architecture = None
    ) -> List[CompileResult]:
        """Compile all C files in output directory.

        Args:
            output_dir: Directory containing generated C files
            arch: Target architecture

        Returns:
            List of CompileResult for each file
        """
        results = []

        # Find all C source files
        c_files = list(output_dir.glob("proxy_*.c"))

        if not c_files:
            print("[!] No proxy_*.c files found in output directory")
            return results

        for c_path in c_files:
            # Find matching .def file
            def_name = c_path.stem + ".def"
            def_path = output_dir / def_name

            if not def_path.exists():
                # Try without _dynamic suffix
                base_name = c_path.stem.replace("_dynamic", "")
                def_path = output_dir / f"{base_name}.def"

            print(f"\n[*] Compiling: {c_path.name}")

            result = self.compile(
                source_path=c_path,
                output_dir=output_dir,
                arch=arch,
                def_path=def_path if def_path.exists() else None
            )

            results.append(result)
            print(f"    {result.summary}")

        return results


def detect_compilers() -> Dict[str, bool]:
    """Detect available compilers on the system.

    Returns:
        Dictionary mapping compiler name to availability
    """
    return {
        "MSVC": MSVCCompiler().is_available(),
        "MinGW": MinGWCompiler().is_available()
    }


def compile_proxy(
    source_path: Path,
    output_dir: Path = None,
    arch: Architecture = None
) -> CompileResult:
    """Convenience function to compile a single proxy source file.

    Args:
        source_path: Path to C source file
        output_dir: Output directory (defaults to source directory)
        arch: Target architecture (auto-detect if None)

    Returns:
        CompileResult
    """
    if output_dir is None:
        output_dir = source_path.parent

    compiler = AutoCompiler()
    return compiler.compile(source_path, output_dir, arch)
