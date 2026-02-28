# -*- coding: utf-8 -*-
"""
luodllhack/core/signatures/ - 统一签名系统

整合了 DLL 劫持和漏洞挖掘的签名提取功能，提供：
- 统一的数据模型 (FunctionSignature, ArgInfo)
- 多种提取器 (Pefile, Angr, Disasm)
- 外部签名加载 (Cutter/rizin functions.json)

使用方法:
    from luodllhack.core.signatures import (
        FunctionSignature, ArgInfo, CallingConvention,
        SignatureExtractor, SignatureLoader,
        get_signature, get_all_signatures,
    )

    # 方法 1: 自动提取
    sig = get_signature(dll_path, "FunctionName")

    # 方法 2: 使用外部签名文件
    loader = SignatureLoader("functions.json")
    sig = loader.get_signature("FunctionName")

    # 方法 3: 使用提取器
    extractor = SignatureExtractor(dll_path)
    sig = extractor.get_signature("FunctionName")
"""

from .models import (
    CallingConvention,
    ArgInfo,
    ArgumentInfo,  # 别名
    FunctionSignature,
    ExportSymbol,  # 别名
)

# 延迟导入以避免循环依赖
def _lazy_import_extractors():
    """延迟导入提取器"""
    from .extractors import (
        SignatureExtractor,
        PefileExtractor,
        DisasmAnalyzer,
        CompositeExtractor,
    )
    return SignatureExtractor, PefileExtractor, DisasmAnalyzer, CompositeExtractor


def _lazy_import_loader():
    """延迟导入加载器"""
    from .loader import (
        SignatureLoader,
        LoadedSignature,
        load_signatures_for_dll,
    )
    return SignatureLoader, LoadedSignature, load_signatures_for_dll


# 便捷函数
def get_signature(dll_path, func_name: str, signature_file=None) -> FunctionSignature:
    """
    获取函数签名 (统一入口)

    优先级:
    1. 外部签名文件 (如果提供或自动检测到)
    2. 反汇编分析
    3. PE 导出表分析

    Args:
        dll_path: DLL 路径
        func_name: 函数名
        signature_file: 外部签名文件路径 (可选)

    Returns:
        FunctionSignature 对象
    """
    from pathlib import Path
    dll_path = Path(dll_path)

    # 尝试从外部签名文件加载 (仅当显式提供时)
    if signature_file:
        try:
            SignatureLoader, _, load_signatures_for_dll = _lazy_import_loader()
            loader = load_signatures_for_dll(
                dll_path,
                Path(signature_file),
                auto_detect=False
            )
            if loader and loader.is_loaded:
                sig = loader.get_function_signature(func_name)
                if sig:
                    return sig
        except Exception:
            pass

    # 回退到提取器
    try:
        SignatureExtractor, _, _, _ = _lazy_import_extractors()
        extractor = SignatureExtractor(dll_path)
        return extractor.get_signature(func_name)
    except Exception:
        pass

    # 最后回退: 返回基本签名
    return FunctionSignature(name=func_name)


def get_all_signatures(dll_path, signature_file=None):
    """
    获取 DLL 的所有函数签名

    Args:
        dll_path: DLL 路径
        signature_file: 外部签名文件路径 (可选)

    Returns:
        Dict[str, FunctionSignature]
    """
    from pathlib import Path
    dll_path = Path(dll_path)

    signatures = {}

    # 首先从提取器获取所有导出
    try:
        SignatureExtractor, _, _, _ = _lazy_import_extractors()
        extractor = SignatureExtractor(dll_path)
        for sig in extractor.get_all_signatures():
            signatures[sig.name] = sig
    except Exception:
        pass

    # 然后用外部签名覆盖/增强 (仅当显式提供时)
    if signature_file:
        try:
            SignatureLoader, _, load_signatures_for_dll = _lazy_import_loader()
            loader = load_signatures_for_dll(
                dll_path,
                Path(signature_file),
                auto_detect=False
            )
            if loader and loader.is_loaded:
                for name, loaded_sig in loader.get_all_signatures().items():
                    sig = loader.get_function_signature(name)
                    if sig:
                        signatures[name] = sig
        except Exception:
            pass

    return signatures


# 别名函数，保持兼容性
def get_function_signature(dll_path, func_name: str, signature_file=None) -> FunctionSignature:
    """
    获取函数签名 (别名)

    与 get_signature 相同，保持向后兼容。
    """
    return get_signature(dll_path, func_name, signature_file)


def get_enhanced_signature(dll_path, func_name: str, rva: int = 0,
                           signature_file=None) -> FunctionSignature:
    """
    获取增强的函数签名

    优先级:
    1. 外部签名文件 (如果提供或自动检测到)
    2. 反汇编分析
    3. PE 导出表分析

    Args:
        dll_path: DLL 路径
        func_name: 函数名
        rva: 函数 RVA (如果为 0 则自动查找)
        signature_file: 外部签名文件路径 (可选)

    Returns:
        FunctionSignature 对象
    """
    return get_signature(dll_path, func_name, signature_file)


__all__ = [
    # 数据模型
    'CallingConvention',
    'ArgInfo',
    'ArgumentInfo',
    'FunctionSignature',
    'ExportSymbol',

    # 便捷函数
    'get_signature',
    'get_all_signatures',
    'get_function_signature',
    'get_enhanced_signature',
]


# 动态添加延迟导入的类到 __all__
def __getattr__(name):
    """支持延迟导入"""
    if name in ('SignatureExtractor', 'PefileExtractor', 'DisasmAnalyzer', 'CompositeExtractor'):
        extractors = _lazy_import_extractors()
        mapping = {
            'SignatureExtractor': extractors[0],
            'PefileExtractor': extractors[1],
            'DisasmAnalyzer': extractors[2],
            'CompositeExtractor': extractors[3],
        }
        return mapping[name]

    if name in ('SignatureLoader', 'LoadedSignature', 'load_signatures_for_dll'):
        loader_items = _lazy_import_loader()
        mapping = {
            'SignatureLoader': loader_items[0],
            'LoadedSignature': loader_items[1],
            'load_signatures_for_dll': loader_items[2],
        }
        return mapping[name]

    raise AttributeError(f"module 'luodllhack.core.signatures' has no attribute '{name}'")
