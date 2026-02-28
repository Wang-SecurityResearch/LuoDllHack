# -*- coding: utf-8 -*-
"""
luodllhack/dll_hijack/scanner.py - DLL 劫持漏洞扫描器

扫描 PE 文件的 DLL 依赖，识别潜在的 DLL 劫持风险。

功能：
1. 递归扫描目录中的 PE 文件
2. 解析导入表和延迟加载表
3. 校验 DLL 在系统目录的存在性
4. 检查目录写入权限
5. 风险分级 (高/中/低/无)
6. 输出报告 (Console/CSV)

用法：
    scanner = HijackScanner()
    results = scanner.scan("C:\\Program Files\\App")
    scanner.print_report(results)
    scanner.export_csv(results, "report.csv")
"""

import os
import sys
import csv
import ctypes
import logging
import platform
import tempfile
import winreg
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, NamedTuple, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pefile
except ImportError:
    pefile = None

logger = logging.getLogger(__name__)


# =============================================================================
# 数据结构定义
# =============================================================================

class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"  # 严重：DLL不存在 + 目录可写
    HIGH = "high"          # 高危：DLL在低优先级目录 + 目录可写
    MEDIUM = "medium"      # 中危：DLL存在但可被劫持
    LOW = "low"            # 低危：理论上可劫持但条件苛刻
    NONE = "none"          # 无风险
    UNKNOWN = "unknown"    # 无法判断


class TriggerType(Enum):
    """触发类型"""
    STARTUP = "startup"           # 程序启动即加载
    DELAY_LOAD = "delay_load"     # 延迟加载，调用特定函数时触发
    DYNAMIC = "dynamic"           # 动态加载 (LoadLibrary)
    UNKNOWN = "unknown"           # 无法判断


@dataclass
class DllDependency:
    """DLL 依赖信息"""
    name: str                          # DLL 名称
    is_delay_load: bool = False        # 是否延迟加载
    imported_functions: List[str] = field(default_factory=list)  # 导入的函数
    system_path: Optional[str] = None  # 系统目录中的路径 (如存在)
    exists_in_system: bool = False     # 是否存在于系统目录
    is_known_dll: bool = False         # 是否在 KnownDLLs 列表
    is_api_set: bool = False           # 是否是 API Set (api-ms-win-*)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_reason: str = ""
    # 触发分析
    trigger_type: TriggerType = TriggerType.UNKNOWN
    trigger_hint: str = ""             # 触发条件描述 (如：调用哪个函数触发)


@dataclass
class PEScanResult:
    """PE 文件扫描结果"""
    path: Path                         # PE 文件路径
    is_64bit: bool = False             # 是否 64 位
    is_dll: bool = False               # 是否 DLL
    dir_writable: bool = False         # 所在目录是否可写
    dependencies: List[DllDependency] = field(default_factory=list)
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    parse_error: Optional[str] = None  # 解析错误
    is_packed: bool = False            # 是否加壳


@dataclass
class ScanSummary:
    """扫描汇总"""
    total_files: int = 0
    pe_files: int = 0
    scan_errors: int = 0
    critical_risk: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0


# =============================================================================
# 系统信息缓存
# =============================================================================

class SystemInfo:
    """系统信息缓存（单例）"""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.is_64bit_os = platform.machine().endswith('64')
        self.is_wow64 = self._check_wow64()

        # 系统目录
        self.system32 = Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'System32'
        self.syswow64 = Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'SysWOW64'
        self.windows_dir = Path(os.environ.get('SystemRoot', 'C:\\Windows'))

        # 缓存
        self._system32_dlls: Optional[Set[str]] = None
        self._syswow64_dlls: Optional[Set[str]] = None
        self._known_dlls: Optional[Set[str]] = None
        self._known_dlls_32: Optional[Set[str]] = None

    def _check_wow64(self) -> bool:
        """检查是否在 WoW64 下运行"""
        if not self.is_64bit_os:
            return False
        # 32位Python在64位系统上
        return platform.architecture()[0] == '32bit'

    def get_system32_dlls(self) -> Set[str]:
        """获取 System32 目录中的 DLL 列表"""
        if self._system32_dlls is None:
            self._system32_dlls = self._scan_dll_dir(self.system32)
        return self._system32_dlls

    def get_syswow64_dlls(self) -> Set[str]:
        """获取 SysWOW64 目录中的 DLL 列表"""
        if self._syswow64_dlls is None:
            if self.syswow64.exists():
                self._syswow64_dlls = self._scan_dll_dir(self.syswow64)
            else:
                self._syswow64_dlls = set()
        return self._syswow64_dlls

    def _scan_dll_dir(self, directory: Path) -> Set[str]:
        """扫描目录中的 DLL 文件"""
        dlls = set()
        try:
            # 禁用 WoW64 重定向以获取真实文件列表
            with self._disable_wow64_redirect():
                for f in directory.iterdir():
                    if f.suffix.lower() == '.dll':
                        dlls.add(f.name.lower())
        except PermissionError:
            logger.warning(f"无权限访问目录: {directory}")
        except Exception as e:
            logger.warning(f"扫描目录失败 {directory}: {e}")
        return dlls

    def get_known_dlls(self, is_32bit: bool = False) -> Set[str]:
        """获取 KnownDLLs 列表"""
        if is_32bit and self.is_64bit_os:
            if self._known_dlls_32 is None:
                self._known_dlls_32 = self._read_known_dlls(
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32"
                )
                # 32位也继承64位的 KnownDLLs
                self._known_dlls_32.update(self.get_known_dlls(is_32bit=False))
            return self._known_dlls_32
        else:
            if self._known_dlls is None:
                self._known_dlls = self._read_known_dlls(
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
                )
            return self._known_dlls

    def _read_known_dlls(self, key_path: str) -> Set[str]:
        """从注册表读取 KnownDLLs"""
        known = set()
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if isinstance(value, str) and value.lower().endswith('.dll'):
                        known.add(value.lower())
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception as e:
            logger.debug(f"读取 KnownDLLs 失败: {e}")
        return known

    class _disable_wow64_redirect:
        """上下文管理器：临时禁用 WoW64 文件系统重定向"""
        def __init__(self):
            self.old_value = ctypes.c_void_p()
            self.success = False

        def __enter__(self):
            if platform.machine().endswith('64') and platform.architecture()[0] == '32bit':
                try:
                    kernel32 = ctypes.windll.kernel32
                    self.success = kernel32.Wow64DisableWow64FsRedirection(
                        ctypes.byref(self.old_value)
                    )
                except Exception:
                    pass
            return self

        def __exit__(self, *args):
            if self.success:
                try:
                    kernel32 = ctypes.windll.kernel32
                    kernel32.Wow64RevertWow64FsRedirection(self.old_value)
                except Exception:
                    pass


# =============================================================================
# PE 文件分析器
# =============================================================================

class PEAnalyzer:
    """PE 文件分析器"""

    # 常见加壳特征 Section 名称
    PACKED_SECTIONS = {
        'upx0', 'upx1', 'upx2', '.upx',           # UPX
        '.aspack', '.adata', 'aspack',             # ASPack
        '.nsp0', '.nsp1', '.nsp2',                 # NsPack
        'pec1', 'pec2', 'pecloak',                 # PECompact
        '.petite',                                  # Petite
        '.vmp0', '.vmp1', '.vmp2',                 # VMProtect
        '.themida',                                 # Themida
        'enigma1', 'enigma2',                      # Enigma
    }

    # API Set 前缀
    API_SET_PREFIXES = ('api-ms-win-', 'ext-ms-win-', 'api-ms-onecoreuap-')

    def __init__(self):
        self.sys_info = SystemInfo()

    def analyze(self, pe_path: Path) -> PEScanResult:
        """分析 PE 文件"""
        result = PEScanResult(path=pe_path)

        if pefile is None:
            result.parse_error = "pefile 模块未安装"
            return result

        try:
            pe = pefile.PE(str(pe_path), fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
            ])

            # 基本信息
            result.is_64bit = pe.FILE_HEADER.Machine == 0x8664  # AMD64
            result.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

            # 检查加壳
            result.is_packed = self._check_packed(pe)

            # 检查目录权限
            result.dir_writable = self._check_dir_writable(pe_path.parent)

            # 解析导入表
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []
                    for imp in entry.imports:
                        if imp.name:
                            functions.append(imp.name.decode('utf-8', errors='ignore'))

                    dep = self._analyze_dependency(
                        dll_name, functions,
                        is_delay_load=False,
                        is_64bit=result.is_64bit,
                        exe_dir=pe_path.parent,
                        dir_writable=result.dir_writable
                    )
                    result.dependencies.append(dep)

            # 解析延迟加载表
            if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []
                    for imp in entry.imports:
                        if imp.name:
                            functions.append(imp.name.decode('utf-8', errors='ignore'))

                    dep = self._analyze_dependency(
                        dll_name, functions,
                        is_delay_load=True,
                        is_64bit=result.is_64bit,
                        exe_dir=pe_path.parent,
                        dir_writable=result.dir_writable
                    )
                    result.dependencies.append(dep)

            pe.close()

            # 统计风险
            for dep in result.dependencies:
                if dep.risk_level == RiskLevel.CRITICAL:
                    result.high_risk_count += 1
                elif dep.risk_level == RiskLevel.HIGH:
                    result.high_risk_count += 1
                elif dep.risk_level == RiskLevel.MEDIUM:
                    result.medium_risk_count += 1
                elif dep.risk_level == RiskLevel.LOW:
                    result.low_risk_count += 1

        except pefile.PEFormatError as e:
            result.parse_error = f"PE 格式错误: {e}"
        except Exception as e:
            result.parse_error = f"解析失败: {e}"

        return result

    def _check_packed(self, pe) -> bool:
        """检查是否加壳"""
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore').lower()
            if name in self.PACKED_SECTIONS:
                return True

        # 检查熵值（加壳文件通常熵值较高）
        for section in pe.sections:
            entropy = section.get_entropy()
            if entropy > 7.5:  # 高熵值
                return True

        return False

    def _check_dir_writable(self, directory: Path) -> bool:
        """检查目录是否可写"""
        try:
            # 尝试创建临时文件
            test_file = directory / f".luodllhack_test_{os.getpid()}.tmp"
            test_file.touch()
            test_file.unlink()
            return True
        except (PermissionError, OSError):
            return False

    def _analyze_dependency(self, dll_name: str, functions: List[str],
                           is_delay_load: bool, is_64bit: bool,
                           exe_dir: Path, dir_writable: bool) -> DllDependency:
        """分析单个 DLL 依赖"""
        dep = DllDependency(
            name=dll_name,
            is_delay_load=is_delay_load,
            imported_functions=functions[:10]  # 只保留前10个
        )

        dll_lower = dll_name.lower()

        # 检查是否是 API Set
        if dll_lower.startswith(self.API_SET_PREFIXES):
            dep.is_api_set = True
            dep.risk_level = RiskLevel.NONE
            dep.risk_reason = "API Set (虚拟DLL)"
            # 即使无法劫持，也分析触发类型（用于完整报告）
            dep.trigger_type, dep.trigger_hint = self._analyze_trigger(
                dep, functions, is_delay_load
            )
            return dep

        # 特殊保护的 DLL (内核加载，不在 KnownDLLs 但无法劫持)
        KERNEL_PROTECTED_DLLS = {'ntdll.dll', 'kernel32.dll', 'kernelbase.dll'}
        if dll_lower in KERNEL_PROTECTED_DLLS:
            dep.is_known_dll = True  # 标记为受保护
            dep.risk_level = RiskLevel.NONE
            dep.risk_reason = "内核保护 (无法劫持)"
            dep.trigger_type, dep.trigger_hint = self._analyze_trigger(
                dep, functions, is_delay_load
            )
            return dep

        # 检查是否在 KnownDLLs
        known_dlls = self.sys_info.get_known_dlls(is_32bit=not is_64bit)
        if dll_lower in known_dlls:
            dep.is_known_dll = True
            dep.risk_level = RiskLevel.NONE
            dep.risk_reason = "KnownDLLs 保护"
            dep.trigger_type, dep.trigger_hint = self._analyze_trigger(
                dep, functions, is_delay_load
            )
            return dep

        # 检查系统目录
        if is_64bit:
            system_dlls = self.sys_info.get_system32_dlls()
            system_dir = self.sys_info.system32
        else:
            if self.sys_info.is_64bit_os:
                system_dlls = self.sys_info.get_syswow64_dlls()
                system_dir = self.sys_info.syswow64
            else:
                system_dlls = self.sys_info.get_system32_dlls()
                system_dir = self.sys_info.system32

        if dll_lower in system_dlls:
            dep.exists_in_system = True
            dep.system_path = str(system_dir / dll_name)

        # 检查 EXE 目录是否已存在该 DLL
        exe_dll_path = exe_dir / dll_name
        exists_in_exe_dir = exe_dll_path.exists()

        # 风险分级
        dep.risk_level, dep.risk_reason = self._classify_risk(
            dep, dir_writable, exists_in_exe_dir
        )

        # 触发分析
        dep.trigger_type, dep.trigger_hint = self._analyze_trigger(
            dep, functions, is_delay_load
        )

        return dep

    def _classify_risk(self, dep: DllDependency, dir_writable: bool,
                      exists_in_exe_dir: bool) -> Tuple[RiskLevel, str]:
        """风险分级"""

        # 如果 EXE 目录不可写，基本无风险
        if not dir_writable:
            return RiskLevel.NONE, "目录不可写"

        # 如果 DLL 已存在于 EXE 目录
        if exists_in_exe_dir:
            return RiskLevel.LOW, "DLL 已存在于应用目录 (可能被替换)"

        # DLL 不存在于系统目录 - 严重风险
        if not dep.exists_in_system:
            if dep.is_delay_load:
                return RiskLevel.CRITICAL, "延迟加载DLL不存在 + 目录可写"
            else:
                return RiskLevel.CRITICAL, "依赖DLL不存在 + 目录可写"

        # DLL 存在于系统目录，但应用目录可写
        # 应用目录优先级高于系统目录
        if dep.is_delay_load:
            return RiskLevel.HIGH, "延迟加载可被劫持 (应用目录优先)"
        else:
            return RiskLevel.MEDIUM, "可被劫持 (应用目录优先级高于系统目录)"

    def _analyze_trigger(self, dep: DllDependency, functions: List[str],
                        is_delay_load: bool) -> Tuple[TriggerType, str]:
        """分析 DLL 加载的触发条件

        返回:
            (TriggerType, trigger_hint): 触发类型和描述
        """
        if is_delay_load:
            # 延迟加载：需要调用特定函数才会触发
            if functions:
                # 分析函数语义，提供触发提示
                hint = self._generate_delay_load_hint(dep.name, functions)
                return TriggerType.DELAY_LOAD, hint
            else:
                return TriggerType.DELAY_LOAD, f"调用 {dep.name} 的任意导出函数时触发"
        else:
            # 静态导入：程序启动时即加载
            return TriggerType.STARTUP, "程序启动时自动加载"

    def _generate_delay_load_hint(self, dll_name: str, functions: List[str]) -> str:
        """生成延迟加载的触发提示

        基于函数名推断何时会触发 DLL 加载
        """
        dll_lower = dll_name.lower()
        hints = []

        # 常见 DLL 的触发场景
        TRIGGER_SCENARIOS = {
            'winhttp.dll': '发起 HTTP 请求',
            'wininet.dll': '访问网络/下载',
            'urlmon.dll': '下载文件/解析URL',
            'ws2_32.dll': '建立网络连接',
            'crypt32.dll': '加密/证书操作',
            'wintrust.dll': '验证文件签名',
            'msi.dll': '安装程序操作',
            'version.dll': '查询文件版本',
            'dbghelp.dll': '调试/崩溃转储',
            'imagehlp.dll': 'PE文件操作',
            'uxtheme.dll': '界面主题绘制',
            'dwmapi.dll': '窗口合成效果',
            'propsys.dll': '文件属性操作',
            'shell32.dll': 'Shell功能调用',
            'oleaut32.dll': 'COM/自动化操作',
            'secur32.dll': '安全/认证操作',
            'dnsapi.dll': 'DNS查询',
            'netapi32.dll': '网络管理操作',
            'wtsapi32.dll': '终端服务操作',
            'userenv.dll': '用户配置操作',
            'setupapi.dll': '设备安装操作',
            'wevtapi.dll': '事件日志操作',
            'pdh.dll': '性能计数器查询',
            'cabinet.dll': 'CAB压缩/解压',
            'mpr.dll': '网络资源操作',
            'shlwapi.dll': 'Shell工具函数',
        }

        # 检查是否有已知场景
        if dll_lower in TRIGGER_SCENARIOS:
            hints.append(TRIGGER_SCENARIOS[dll_lower])

        # 从函数名推断场景
        for func in functions[:5]:  # 只检查前5个
            func_lower = func.lower()
            if 'connect' in func_lower or 'open' in func_lower:
                hints.append(f'调用 {func}')
            elif 'create' in func_lower:
                hints.append(f'创建操作 ({func})')
            elif 'get' in func_lower or 'query' in func_lower:
                hints.append(f'查询操作 ({func})')
            elif 'init' in func_lower:
                hints.append(f'初始化时 ({func})')

        if hints:
            return '触发: ' + '; '.join(hints[:3])  # 最多3个提示
        else:
            # 默认提示
            func_list = ', '.join(functions[:3])
            if len(functions) > 3:
                func_list += f' 等{len(functions)}个函数'
            return f'调用以下函数时触发: {func_list}'


# =============================================================================
# AI 触发分析（可选）
# =============================================================================

class TriggerAnalyzerAI:
    """
    AI 增强的触发分析器（可选功能）

    采用"全局视角"分析策略：
    1. 首先分析目标程序是什么、做什么
    2. 基于程序功能推断各 DLL 的触发时机
    3. 生成具体的利用场景

    需要配置 AI API。
    """

    # 程序分析提示模板 - 全局视角
    PROGRAM_ANALYSIS_PROMPT = '''你是一名安全研究员，正在分析一个 Windows 程序的 DLL 劫持攻击面。

## 目标程序信息
- 文件名: {exe_name}
- 文件路径: {exe_path}
- 架构: {arch}
- 版本信息: {version_info}

## 导入的 DLL（部分）
{all_dlls}

## 可劫持的 DLL（高/中风险）
{risky_dlls}

---

请完成以下分析：

### 1. 程序识别
这个程序是什么？属于哪类软件？（如：浏览器、IDE、游戏、办公软件、系统工具等）

### 2. 核心功能推断
基于导入的 DLL，这个程序可能有哪些主要功能？

### 3. DLL 触发场景分析
对于每个可劫持的 DLL，分析：
- **触发时机**: 用户执行什么操作会加载这个 DLL？
- **触发难度**: 容易/中等/困难
- **用户交互**: 需要用户做什么？

### 4. 最佳攻击路径
如果要利用这个程序进行 DLL 劫持，推荐哪个 DLL？为什么？

请用中文简洁回答，重点关注实际可操作的触发方式。'''

    def __init__(self, api_key: str = None):
        """初始化 AI 触发分析器"""
        self._api_key = api_key
        self._model = None
        self._program_cache = {}  # 缓存程序分析结果
        self._init_model()

    def _init_model(self):
        """初始化 AI 模型"""
        try:
            import google.generativeai as genai
            key = self._api_key or os.environ.get("GEMINI_API_KEY", "")
            if key:
                genai.configure(api_key=key)
                self._model = genai.GenerativeModel('gemini-2.0-flash')
        except ImportError:
            pass

    def is_available(self) -> bool:
        """检查 AI 是否可用"""
        return self._model is not None

    def analyze_program(self, result: PEScanResult) -> Dict[str, Any]:
        """
        全局分析目标程序

        Args:
            result: PE 扫描结果

        Returns:
            程序分析结果，包含程序类型、功能、各 DLL 触发分析
        """
        if not self.is_available():
            return {"error": "AI not available"}

        # 检查缓存
        cache_key = str(result.path)
        if cache_key in self._program_cache:
            return self._program_cache[cache_key]

        # 收集所有 DLL
        all_dlls = []
        for dep in result.dependencies[:20]:  # 限制数量
            all_dlls.append(f"- {dep.name}")

        # 收集高危 DLL
        risky_dlls = []
        for dep in result.dependencies:
            if dep.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
                trigger_info = f"[{dep.trigger_type.name}]" if dep.trigger_type else ""
                funcs = ', '.join(dep.imported_functions[:5]) if dep.imported_functions else "N/A"
                risky_dlls.append(f"- {dep.name} ({dep.risk_level.name}) {trigger_info}")
                risky_dlls.append(f"  导入函数: {funcs}")

        if not risky_dlls:
            return {"error": "No risky DLLs found"}

        # 获取版本信息
        version_info = "未知"
        try:
            import pefile
            pe = pefile.PE(str(result.path), fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            if hasattr(pe, 'FileInfo'):
                for info in pe.FileInfo:
                    for entry in info:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                info_dict = {k.decode(): v.decode() for k, v in st.entries.items()}
                                if 'ProductName' in info_dict:
                                    version_info = f"{info_dict.get('ProductName', '')} {info_dict.get('ProductVersion', '')}"
                                    if 'FileDescription' in info_dict:
                                        version_info += f" - {info_dict['FileDescription']}"
                                    break
            pe.close()
        except Exception:
            pass

        # 构建提示
        prompt = self.PROGRAM_ANALYSIS_PROMPT.format(
            exe_name=result.path.name,
            exe_path=str(result.path.parent),
            arch='x64' if result.is_64bit else 'x86',
            version_info=version_info,
            all_dlls='\n'.join(all_dlls),
            risky_dlls='\n'.join(risky_dlls)
        )

        try:
            response = self._model.generate_content(prompt)
            analysis = {
                "success": True,
                "program": result.path.name,
                "version_info": version_info,
                "analysis": response.text.strip() if response.text else "分析失败"
            }
            # 缓存结果
            self._program_cache[cache_key] = analysis
            return analysis
        except Exception as e:
            logger.debug(f"AI 程序分析失败: {e}")
            return {"error": str(e)}

    def analyze_trigger(self, exe_name: str, dep: DllDependency) -> str:
        """
        兼容旧接口 - 单个 DLL 分析（不推荐，建议使用 analyze_program）
        """
        if not self.is_available():
            return dep.trigger_hint
        return dep.trigger_hint  # 简化实现，推荐使用 analyze_program

    def generate_exploit_scenario(self, result: PEScanResult) -> str:
        """
        为扫描结果生成完整的利用场景描述（使用全局分析）
        """
        analysis = self.analyze_program(result)
        if "error" in analysis:
            # 回退到静态分析
            risky_deps = [d for d in result.dependencies
                          if d.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)]
            if not risky_deps:
                return "无可利用的 DLL 劫持点"

            lines = [f"目标: {result.path.name}"]
            lines.append(f"架构: {'x64' if result.is_64bit else 'x86'}")
            lines.append(f"目录可写: {'是' if result.dir_writable else '否'}")
            lines.append("")
            lines.append("可劫持 DLL:")
            for dep in risky_deps:
                lines.append(f"  [{dep.risk_level.name}] {dep.name}")
                lines.append(f"    触发: {dep.trigger_type.name}")
                lines.append(f"    条件: {dep.trigger_hint}")
            return '\n'.join(lines)

        return analysis.get("analysis", "分析失败")


def analyze_exploitation_trigger(result: PEScanResult, use_ai: bool = False,
                                  api_key: str = None) -> Dict[str, Any]:
    """
    分析 DLL 劫持的利用触发条件

    Args:
        result: PE 扫描结果
        use_ai: 是否使用 AI 增强分析（全局视角）
        api_key: Gemini API Key（可选，也可通过环境变量设置）

    Returns:
        包含利用信息的字典
    """
    exploit_info = {
        'target': str(result.path),
        'architecture': 'x64' if result.is_64bit else 'x86',
        'dir_writable': result.dir_writable,
        'ai_enabled': use_ai,
        'vulnerabilities': []
    }

    # 初始化 AI 分析器（如果启用）
    ai_analyzer = None
    ai_program_analysis = None
    if use_ai:
        ai_analyzer = TriggerAnalyzerAI(api_key=api_key)
        if ai_analyzer.is_available():
            exploit_info['ai_status'] = 'available'
            # 执行全局程序分析（一次性分析整个程序）
            ai_program_analysis = ai_analyzer.analyze_program(result)
            if ai_program_analysis.get('success'):
                exploit_info['ai_analysis'] = ai_program_analysis['analysis']
                exploit_info['version_info'] = ai_program_analysis.get('version_info', '')
        else:
            exploit_info['ai_status'] = 'unavailable (需要 --api-key 或设置 GEMINI_API_KEY)'
            ai_analyzer = None

    for dep in result.dependencies:
        if dep.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
            vuln = {
                'dll': dep.name,
                'risk': dep.risk_level.name,
                'trigger_type': dep.trigger_type.name,
                'trigger_hint': dep.trigger_hint,
                'functions': dep.imported_functions,
                'is_delay_load': dep.is_delay_load,
            }

            # 生成利用步骤（静态规则）
            trigger_hint = dep.trigger_hint
            if dep.trigger_type == TriggerType.STARTUP:
                vuln['exploit_steps'] = [
                    f"1. 生成恶意 {dep.name}（需转发原始导出）",
                    f"2. 将恶意 DLL 放入目标程序目录",
                    f"3. 启动 {result.path.name}，DLL 自动加载",
                ]
            elif dep.trigger_type == TriggerType.DELAY_LOAD:
                vuln['exploit_steps'] = [
                    f"1. 生成恶意 {dep.name}（需转发原始导出）",
                    f"2. 将恶意 DLL 放入目标程序目录",
                    f"3. 启动 {result.path.name}",
                    f"4. {trigger_hint}",
                ]
            else:
                vuln['exploit_steps'] = [
                    f"1. 生成恶意 {dep.name}",
                    f"2. 需要进一步分析触发条件",
                ]

            exploit_info['vulnerabilities'].append(vuln)

    return exploit_info


# =============================================================================
# 文件扫描器
# =============================================================================

class FileScanner:
    """文件扫描器"""

    # 默认跳过的目录
    DEFAULT_SKIP_DIRS = {
        'windows', 'system32', 'syswow64', 'winsxs',
        '$recycle.bin', 'system volume information',
        'programdata', 'appdata',
    }

    def __init__(self, skip_system: bool = True, skip_dirs: Set[str] = None):
        self.skip_system = skip_system
        self.skip_dirs = skip_dirs or self.DEFAULT_SKIP_DIRS

    def scan(self, path: str, recursive: bool = True) -> List[Path]:
        """扫描路径中的 PE 文件"""
        path_obj = Path(path)
        pe_files = []

        # 处理通配符
        if '*' in path or '?' in path:
            import glob
            for match in glob.glob(path, recursive=recursive):
                match_path = Path(match)
                if match_path.is_file() and self._is_pe_file(match_path):
                    pe_files.append(match_path)
            return pe_files

        if not path_obj.exists():
            logger.error(f"路径不存在: {path}")
            return []

        if path_obj.is_file():
            if self._is_pe_file(path_obj):
                return [path_obj]
            return []

        # 目录扫描
        pattern = '**/*' if recursive else '*'
        for item in path_obj.glob(pattern):
            if item.is_file():
                # 跳过检查
                if self._should_skip(item):
                    continue

                if self._is_pe_file(item):
                    pe_files.append(item)

        return pe_files

    def _should_skip(self, path: Path) -> bool:
        """检查是否应跳过"""
        if not self.skip_system:
            return False

        path_lower = str(path).lower()
        for skip_dir in self.skip_dirs:
            if f'\\{skip_dir}\\' in path_lower or path_lower.endswith(f'\\{skip_dir}'):
                return True

        return False

    def _is_pe_file(self, path: Path) -> bool:
        """检查是否是有效的 PE 文件"""
        # 扩展名检查
        suffix = path.suffix.lower()
        if suffix not in ('.exe', '.dll', '.sys', '.ocx', '.scr'):
            return False

        # 文件大小检查
        try:
            if path.stat().st_size < 64:  # PE 头至少 64 字节
                return False
        except OSError:
            return False

        # MZ 魔数检查
        try:
            with open(path, 'rb') as f:
                magic = f.read(2)
                return magic == b'MZ'
        except (PermissionError, OSError):
            return False


# =============================================================================
# 主扫描器
# =============================================================================

class HijackScanner:
    """DLL 劫持漏洞扫描器"""

    def __init__(self, skip_system: bool = True, max_workers: int = 4):
        """
        初始化扫描器

        Args:
            skip_system: 是否跳过系统目录
            max_workers: 并行工作线程数
        """
        self.file_scanner = FileScanner(skip_system=skip_system)
        self.pe_analyzer = PEAnalyzer()
        self.max_workers = max_workers

    def scan(self, path: str, recursive: bool = True,
             risk_filter: Optional[Set[RiskLevel]] = None,
             progress_callback=None) -> Tuple[List[PEScanResult], ScanSummary]:
        """
        扫描指定路径

        Args:
            path: 扫描路径 (支持通配符)
            recursive: 是否递归扫描
            risk_filter: 只返回指定风险等级的结果
            progress_callback: 进度回调 callback(current, total, filename)

        Returns:
            (扫描结果列表, 汇总信息)
        """
        # 扫描文件
        logger.info(f"扫描路径: {path}")
        pe_files = self.file_scanner.scan(path, recursive)

        summary = ScanSummary()
        summary.total_files = len(pe_files)
        summary.pe_files = len(pe_files)

        if not pe_files:
            logger.info("未找到 PE 文件")
            return [], summary

        logger.info(f"找到 {len(pe_files)} 个 PE 文件")

        results = []

        # 并行分析
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.pe_analyzer.analyze, pe): pe for pe in pe_files}

            for i, future in enumerate(as_completed(futures)):
                pe_path = futures[future]

                if progress_callback:
                    progress_callback(i + 1, len(pe_files), pe_path.name)

                try:
                    result = future.result()

                    if result.parse_error:
                        summary.scan_errors += 1

                    # 统计风险
                    for dep in result.dependencies:
                        if dep.risk_level == RiskLevel.CRITICAL:
                            summary.critical_risk += 1
                        elif dep.risk_level == RiskLevel.HIGH:
                            summary.high_risk += 1
                        elif dep.risk_level == RiskLevel.MEDIUM:
                            summary.medium_risk += 1
                        elif dep.risk_level == RiskLevel.LOW:
                            summary.low_risk += 1

                    # 风险过滤
                    if risk_filter:
                        has_risk = any(d.risk_level in risk_filter for d in result.dependencies)
                        if not has_risk and not result.parse_error:
                            continue

                    results.append(result)

                except Exception as e:
                    logger.error(f"分析失败 {pe_path}: {e}")
                    summary.scan_errors += 1

        # 按风险排序
        results.sort(key=lambda r: (
            -r.high_risk_count,
            -r.medium_risk_count,
            -r.low_risk_count
        ))

        return results, summary

    def print_report(self, results: List[PEScanResult], summary: ScanSummary,
                    show_low_risk: bool = False, verbose: bool = False):
        """打印扫描报告"""
        print("\n" + "=" * 70)
        print("  DLL 劫持漏洞扫描报告")
        print("=" * 70)

        print(f"\n[统计]")
        print(f"  扫描文件: {summary.pe_files}")
        print(f"  解析错误: {summary.scan_errors}")
        print(f"  严重风险: {summary.critical_risk}")
        print(f"  高危风险: {summary.high_risk}")
        print(f"  中危风险: {summary.medium_risk}")
        print(f"  低危风险: {summary.low_risk}")

        # 输出高风险结果
        high_risk_results = [r for r in results if r.high_risk_count > 0]
        if high_risk_results:
            print(f"\n[!] 高风险 PE 文件 ({len(high_risk_results)} 个):")
            print("-" * 70)

            for result in high_risk_results[:20]:  # 最多显示 20 个
                print(f"\n  路径: {result.path}")
                print(f"  架构: {'x64' if result.is_64bit else 'x86'} | "
                      f"目录可写: {'是' if result.dir_writable else '否'}")

                for dep in result.dependencies:
                    if dep.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                        risk_icon = "!!!" if dep.risk_level == RiskLevel.CRITICAL else "!!"
                        print(f"    [{risk_icon}] {dep.name}")
                        print(f"        风险: {dep.risk_reason}")
                        if verbose and dep.imported_functions:
                            funcs = ', '.join(dep.imported_functions[:5])
                            print(f"        函数: {funcs}...")

        # 输出中风险结果
        medium_risk_results = [r for r in results if r.medium_risk_count > 0 and r.high_risk_count == 0]
        if medium_risk_results:
            print(f"\n[*] 中风险 PE 文件 ({len(medium_risk_results)} 个):")
            print("-" * 70)

            for result in medium_risk_results[:10]:
                print(f"\n  路径: {result.path}")
                for dep in result.dependencies:
                    if dep.risk_level == RiskLevel.MEDIUM:
                        print(f"    [!] {dep.name} - {dep.risk_reason}")

        # 输出低风险结果
        if show_low_risk:
            low_risk_results = [r for r in results if r.low_risk_count > 0
                               and r.high_risk_count == 0 and r.medium_risk_count == 0]
            if low_risk_results:
                print(f"\n[-] 低风险 PE 文件 ({len(low_risk_results)} 个):")
                for result in low_risk_results[:5]:
                    print(f"  {result.path}")

        # 解析错误
        error_results = [r for r in results if r.parse_error]
        if error_results:
            print(f"\n[?] 解析失败 ({len(error_results)} 个):")
            for result in error_results[:5]:
                print(f"  {result.path}: {result.parse_error}")

        print("\n" + "=" * 70)

    def export_csv(self, results: List[PEScanResult], output_path: str,
                  include_no_risk: bool = False):
        """导出 CSV 报告"""
        with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow([
                'PE路径', '架构', '类型', '目录可写', '加壳',
                'DLL名称', '风险等级', '风险原因', '延迟加载',
                '系统目录存在', 'KnownDLLs', '导入函数'
            ])

            for result in results:
                if result.parse_error:
                    writer.writerow([
                        str(result.path), '', '', '', '',
                        '', 'ERROR', result.parse_error, '', '', '', ''
                    ])
                    continue

                for dep in result.dependencies:
                    if not include_no_risk and dep.risk_level == RiskLevel.NONE:
                        continue

                    writer.writerow([
                        str(result.path),
                        'x64' if result.is_64bit else 'x86',
                        'DLL' if result.is_dll else 'EXE',
                        '是' if result.dir_writable else '否',
                        '是' if result.is_packed else '否',
                        dep.name,
                        dep.risk_level.value,
                        dep.risk_reason,
                        '是' if dep.is_delay_load else '否',
                        '是' if dep.exists_in_system else '否',
                        '是' if dep.is_known_dll else '否',
                        '; '.join(dep.imported_functions[:5])
                    ])

        logger.info(f"CSV 报告已导出: {output_path}")


# =============================================================================
# 便捷函数
# =============================================================================

def scan_for_hijack(path: str, recursive: bool = True,
                   skip_system: bool = True) -> Tuple[List[PEScanResult], ScanSummary]:
    """
    扫描 DLL 劫持漏洞（便捷函数）

    Args:
        path: 扫描路径
        recursive: 是否递归
        skip_system: 是否跳过系统目录

    Returns:
        (结果列表, 汇总)
    """
    scanner = HijackScanner(skip_system=skip_system)
    return scanner.scan(path, recursive)


def quick_check(exe_path: str) -> List[DllDependency]:
    """
    快速检查单个 PE 文件（便捷函数）

    Returns:
        有风险的 DLL 依赖列表
    """
    analyzer = PEAnalyzer()
    result = analyzer.analyze(Path(exe_path))

    return [dep for dep in result.dependencies
            if dep.risk_level not in (RiskLevel.NONE, RiskLevel.UNKNOWN)]


if __name__ == "__main__":
    # 简单测试
    import sys

    if len(sys.argv) < 2:
        print("用法: python scanner.py <路径>")
        sys.exit(1)

    logging.basicConfig(level=logging.INFO)

    scanner = HijackScanner()
    results, summary = scanner.scan(sys.argv[1])
    scanner.print_report(results, summary, verbose=True)
