# -*- coding: utf-8 -*-
"""
luodllhack/core/signatures/loader.py - 外部签名文件加载器

支持从 Cutter/rizin 导出的 functions.json 加载函数签名，
提供比自动分析更准确的签名信息。

使用方法:
    loader = SignatureLoader("functions.json")
    sig = loader.get_function_signature("GetHandlerProperty2")
    if sig:
        print(f"参数数量: {sig.arg_count}")
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging

from .models import FunctionSignature, ArgInfo, CallingConvention

logger = logging.getLogger(__name__)


# COM 接口方法名模式
COM_METHOD_PATTERNS = {
    'QueryInterface', 'AddRef', 'Release',
    'CreateInstance', 'LockServer',
    'Invoke', 'GetIDsOfNames', 'GetTypeInfo', 'GetTypeInfoCount',
    'GetHandlerProperty', 'GetHandlerProperty2', 'GetNumberOfFormats',
    'GetArchiveName', 'CreateObject', 'GetNumberOfMethods',
    'GetMethodProperty', 'GetNumberOfCodecs', 'GetCodecInfo',
}

COM_METHOD_REGEX = re.compile(
    r'^(QueryInterface|AddRef|Release|'
    r'Get[A-Z]\w*|Set[A-Z]\w*|'
    r'Create\w*|Open\w*|Close\w*|'
    r'Read\w*|Write\w*|'
    r'On[A-Z]\w*|'
    r'[A-Z][a-z]+[A-Z]\w*)$'
)


def _is_com_method_name(func_name: str) -> bool:
    """检查函数名是否符合 COM 方法模式"""
    if func_name in COM_METHOD_PATTERNS:
        return True
    if COM_METHOD_REGEX.match(func_name):
        return True
    return False


@dataclass
class LoadedSignature:
    """从外部文件加载的原始签名数据"""
    func_name: str
    arg_count: int
    calling_convention: str = "ms"
    return_type: str = "int64_t"
    args: List[Dict[str, Any]] = field(default_factory=list)
    reg_vars: List[Dict[str, Any]] = field(default_factory=list)
    stack_vars: List[Dict[str, Any]] = field(default_factory=list)
    raw_signature: str = ""
    offset: int = 0
    size: int = 0
    is_pure: bool = False
    source: str = "unknown"


class SignatureLoader:
    """
    签名加载器 - 从外部文件加载函数签名

    支持的格式:
    - Cutter/rizin functions.json (aflj 命令导出)
    - 自定义 YAML/JSON 签名数据库
    """

    def __init__(self, signature_file: Optional[Path] = None, dll_name: str = None):
        """
        初始化签名加载器

        Args:
            signature_file: 签名文件路径 (functions.json)
            dll_name: DLL 名称，用于过滤函数
        """
        self.signature_file = Path(signature_file) if signature_file else None
        self.dll_name = dll_name
        self._loaded_signatures: Dict[str, LoadedSignature] = {}
        self._loaded = False

        if self.signature_file and self.signature_file.exists():
            self._load_signatures()

    def _load_signatures(self) -> None:
        """加载签名文件"""
        if not self.signature_file or not self.signature_file.exists():
            logger.warning(f"Signature file not found: {self.signature_file}")
            return

        suffix = self.signature_file.suffix.lower()

        if suffix == '.json':
            self._load_rizin_json()
        elif suffix in ('.yaml', '.yml'):
            self._load_yaml()
        else:
            logger.warning(f"Unknown signature file format: {suffix}")
            return

        self._loaded = True
        logger.info(f"Loaded {len(self._loaded_signatures)} signatures from {self.signature_file}")

    def _load_rizin_json(self) -> None:
        """加载 Cutter/rizin 的 functions.json 格式"""
        try:
            with open(self.signature_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if not isinstance(data, list):
                logger.error("Invalid functions.json format: expected list")
                return

            for func in data:
                if not isinstance(func, dict):
                    continue

                raw_name = func.get('name', '')
                if not raw_name:
                    continue

                func_name = self._parse_function_name(raw_name)
                if not func_name:
                    continue

                # 如果指定了 DLL 名称，只加载匹配的函数
                if self.dll_name:
                    dll_pattern = self.dll_name.replace('.', r'\.')
                    if not re.search(dll_pattern, raw_name, re.IGNORECASE):
                        continue

                sig = LoadedSignature(
                    func_name=func_name,
                    arg_count=func.get('nargs', 0),
                    calling_convention=func.get('calltype', 'ms'),
                    raw_signature=func.get('signature', ''),
                    offset=func.get('offset', 0),
                    size=func.get('size', 0),
                    is_pure=func.get('is-pure', False),
                    source='rizin'
                )

                sig.args = self._parse_signature_args(func.get('signature', ''))

                reg_vars = func.get('regvars', [])
                for rv in reg_vars:
                    if rv.get('arg', False):
                        sig.reg_vars.append({
                            'name': rv.get('name', ''),
                            'type': rv.get('type', 'int64_t'),
                            'reg': rv.get('storage', {}).get('reg', ''),
                        })

                stack_vars = func.get('stackvars', [])
                for sv in stack_vars:
                    sig.stack_vars.append({
                        'name': sv.get('name', ''),
                        'type': sv.get('type', 'int64_t'),
                        'offset': sv.get('storage', {}).get('stack', 0),
                    })

                self._loaded_signatures[func_name] = sig
                self._loaded_signatures[func_name.lower()] = sig
                self._loaded_signatures[raw_name] = sig

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse functions.json: {e}")
        except Exception as e:
            logger.error(f"Failed to load signatures: {e}")

    def _parse_function_name(self, raw_name: str) -> str:
        """解析函数名"""
        name = raw_name
        if name.startswith('sym.imp.'):
            name = name[8:]
        elif name.startswith('sym.'):
            name = name[4:]

        match = re.search(r'\.dll_(.+)$', name, re.IGNORECASE)
        if match:
            return match.group(1)

        match = re.search(r'[^_]+_(.+)$', name)
        if match and not name.startswith('fcn.'):
            return match.group(1)

        return name

    def _parse_signature_args(self, signature: str) -> List[Dict[str, Any]]:
        """解析签名字符串中的参数"""
        args = []
        match = re.search(r'\(([^)]*)\)', signature)
        if not match:
            return args

        params_str = match.group(1).strip()
        if not params_str or params_str == 'void':
            return args

        params = params_str.split(',')
        for param in params:
            param = param.strip()
            if not param:
                continue

            parts = param.rsplit(' ', 1)
            if len(parts) == 2:
                args.append({
                    'type': parts[0].strip(),
                    'name': parts[1].strip(),
                })
            else:
                args.append({
                    'type': param,
                    'name': f'arg{len(args) + 1}',
                })

        return args

    def _load_yaml(self) -> None:
        """加载 YAML 格式的签名文件"""
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML not installed")
            return

        try:
            with open(self.signature_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict):
                return

            for dll_name, functions in data.items():
                if not isinstance(functions, dict):
                    continue

                for func_name, func_info in functions.items():
                    if not isinstance(func_info, dict):
                        continue

                    args = []
                    raw_args = func_info.get('args', [])
                    for i, arg in enumerate(raw_args):
                        if isinstance(arg, str):
                            args.append({'type': arg, 'name': f'arg{i+1}'})
                        elif isinstance(arg, dict):
                            args.append(arg)

                    sig = LoadedSignature(
                        func_name=func_name,
                        arg_count=len(args),
                        calling_convention=func_info.get('convention', 'stdcall'),
                        return_type=func_info.get('return_type', 'HRESULT'),
                        args=args,
                        raw_signature=func_info.get('signature', ''),
                        source='yaml'
                    )

                    self._loaded_signatures[func_name] = sig
                    self._loaded_signatures[func_name.lower()] = sig

        except Exception as e:
            logger.error(f"Failed to load YAML signatures: {e}")

    def get_signature(self, func_name: str) -> Optional[LoadedSignature]:
        """获取原始加载的签名"""
        if func_name in self._loaded_signatures:
            return self._loaded_signatures[func_name]
        if func_name.lower() in self._loaded_signatures:
            return self._loaded_signatures[func_name.lower()]
        if self.dll_name:
            prefixed_name = f"sym.{self.dll_name}_{func_name}"
            if prefixed_name in self._loaded_signatures:
                return self._loaded_signatures[prefixed_name]
        return None

    def get_function_signature(self, func_name: str) -> Optional[FunctionSignature]:
        """获取转换后的 FunctionSignature 对象"""
        loaded_sig = self.get_signature(func_name)
        if not loaded_sig:
            return None

        # 转换参数
        args = []
        for i, arg_data in enumerate(loaded_sig.args):
            arg_type = arg_data.get('type', 'int64_t')
            is_ptr = '*' in arg_type or 'ptr' in arg_type.lower()

            # 确定 ctype
            ctype = 'c_int64'
            if is_ptr:
                ctype = 'c_void_p'
            elif 'int32' in arg_type or arg_type in ('int', 'DWORD', 'UINT', 'LONG'):
                ctype = 'c_int32'
            elif 'uint32' in arg_type or arg_type == 'ULONG':
                ctype = 'c_uint32'

            args.append(ArgInfo(
                index=i,
                location=['rcx', 'rdx', 'r8', 'r9'][i] if i < 4 else f'stack+{0x28 + (i-4)*8:x}',
                size=8,
                type_hint='ptr' if is_ptr else 'int',
                is_pointer=is_ptr,
                is_output=arg_data.get('is_output', False),
                dereferenced=is_ptr,
                ctype=ctype,
                name_hint=arg_data.get('name', f'arg{i+1}'),
            ))

        # 如果没有解析出参数但 arg_count > 0
        if not args and loaded_sig.arg_count > 0:
            for i in range(loaded_sig.arg_count):
                args.append(ArgInfo(
                    index=i,
                    location=['rcx', 'rdx', 'r8', 'r9'][i] if i < 4 else f'stack+{0x28 + (i-4)*8:x}',
                    size=8,
                    type_hint='int',
                    ctype='c_int64',
                    name_hint=f'arg{i+1}',
                ))

        # 转换调用约定
        cc = CallingConvention.from_string(loaded_sig.calling_convention)

        # 转换返回类型
        return_type = 'int64'
        rt = loaded_sig.return_type.lower()
        if 'hresult' in rt:
            return_type = 'hresult'
        elif 'void' in rt and '*' not in rt:
            return_type = 'void'
        elif '*' in rt or 'ptr' in rt:
            return_type = 'ptr'
        elif 'bool' in rt:
            return_type = 'bool'

        sig = FunctionSignature(
            name=loaded_sig.func_name,
            rva=loaded_sig.offset,
            calling_convention=cc,
            arg_count=loaded_sig.arg_count,
            args=args,
            return_type=return_type,
            is_com_method=_is_com_method_name(func_name),
            confidence=0.9,  # 外部签名置信度高
            analysis_source='external',
            signature_source=loaded_sig.source,
            raw_signature=loaded_sig.raw_signature,
        )

        logger.info(f"[SignatureLoader] Loaded signature for {func_name}: "
                    f"{sig.arg_count} args, source={loaded_sig.source}")

        return sig

    def has_signature(self, func_name: str) -> bool:
        """检查是否有指定函数的签名"""
        return self.get_signature(func_name) is not None

    def get_all_signatures(self) -> Dict[str, LoadedSignature]:
        """获取所有签名 (去重)"""
        result = {}
        for name, sig in self._loaded_signatures.items():
            if sig.func_name not in result:
                result[sig.func_name] = sig
        return result

    @property
    def is_loaded(self) -> bool:
        """检查是否已加载签名"""
        return self._loaded and len(self._loaded_signatures) > 0

    def __len__(self) -> int:
        return len(self.get_all_signatures())

    def __contains__(self, func_name: str) -> bool:
        return self.has_signature(func_name)


def load_signatures_for_dll(dll_path: Path, signature_file: Path = None,
                            auto_detect: bool = True) -> Optional[SignatureLoader]:
    """
    为 DLL 加载签名

    Args:
        dll_path: DLL 文件路径
        signature_file: 签名文件路径 (可选)
        auto_detect: 是否自动检测签名文件

    Returns:
        SignatureLoader 实例或 None
    """
    dll_path = Path(dll_path)
    dll_name = dll_path.name

    if signature_file and Path(signature_file).exists():
        return SignatureLoader(signature_file, dll_name)

    if auto_detect:
        search_paths = [
            dll_path.parent / 'functions.json',
            dll_path.parent / f'{dll_path.stem}_functions.json',
            dll_path.parent / f'{dll_path.stem}.json',
            Path.cwd() / 'functions.json',
            Path.cwd() / f'{dll_path.stem}_functions.json',
        ]

        for path in search_paths:
            if path.exists():
                logger.info(f"Auto-detected signature file: {path}")
                return SignatureLoader(path, dll_name)

    return None
