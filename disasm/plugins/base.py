# -*- coding: utf-8 -*-
"""
disasm/plugins/base.py - 插件基类和管理器

插件开发指南:
1. 继承 PluginBase 类
2. 实现 analyze() 方法
3. 放置在 plugins/ 目录下
4. 使用 PluginManager.load_plugins() 加载
"""

import os
import importlib
import importlib.util
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional

from ..engine import DisasmEngine, Function, Instruction


class PluginBase(ABC):
    """
    插件基类

    所有插件必须继承此类并实现 analyze() 方法

    示例:
        class MyPlugin(PluginBase):
            name = "my_plugin"
            description = "自定义分析插件"
            version = "1.0"

            def analyze(self, engine, target):
                # 分析逻辑
                return {"result": "..."}
    """

    name: str = "base_plugin"
    description: str = "Base plugin"
    version: str = "1.0"
    author: str = "Unknown"

    def __init__(self):
        self.engine: Optional[DisasmEngine] = None
        self.results: Dict[str, Any] = {}

    def initialize(self, engine: DisasmEngine):
        """初始化插件"""
        self.engine = engine

    @abstractmethod
    def analyze(self, target: Any) -> Dict[str, Any]:
        """
        执行分析

        Args:
            target: 分析目标 (地址、函数、指令列表等)

        Returns:
            分析结果字典
        """
        pass

    def on_instruction(self, insn: Instruction) -> Optional[Dict]:
        """
        指令回调 (可选)

        在遍历指令时调用，用于流式分析
        """
        return None

    def on_function(self, func: Function) -> Optional[Dict]:
        """
        函数回调 (可选)

        在分析完函数后调用
        """
        return None

    def get_commands(self) -> Dict[str, callable]:
        """
        获取插件提供的交互式命令 (可选)

        Returns:
            命令字典 {命令名: 处理函数}
        """
        return {}

    def cleanup(self):
        """清理资源"""
        pass


class PluginManager:
    """
    插件管理器

    负责加载、管理和执行插件

    用法:
        manager = PluginManager()
        manager.load_plugins()  # 加载 plugins/ 目录下的所有插件
        manager.run_plugin("my_plugin", engine, target)
    """

    def __init__(self, plugin_dir: Path = None):
        self.plugin_dir = plugin_dir or Path(__file__).parent
        self.plugins: Dict[str, PluginBase] = {}
        self.loaded = False

    def load_plugins(self) -> List[str]:
        """
        加载所有插件

        Returns:
            已加载的插件名列表
        """
        loaded = []

        for file in self.plugin_dir.glob("*.py"):
            if file.name.startswith("_") or file.name == "base.py":
                continue

            try:
                plugin = self._load_plugin_file(file)
                if plugin:
                    self.plugins[plugin.name] = plugin
                    loaded.append(plugin.name)
            except Exception as e:
                print(f"[!] 加载插件失败 {file.name}: {e}")

        self.loaded = True
        return loaded

    def _load_plugin_file(self, path: Path) -> Optional[PluginBase]:
        """从文件加载插件"""
        import sys

        # 确保父包在 sys.path 中
        parent_dir = str(path.parent.parent.parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)

        # 使用包名加载以支持相对导入
        module_name = f"disasm.plugins.{path.stem}"

        try:
            # 尝试通过包名导入
            import importlib
            module = importlib.import_module(module_name)
        except ImportError:
            # 回退到文件加载
            spec = importlib.util.spec_from_file_location(path.stem, path)
            if not spec or not spec.loader:
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

        # 查找 PluginBase 子类
        for name in dir(module):
            obj = getattr(module, name)
            if (isinstance(obj, type) and
                issubclass(obj, PluginBase) and
                obj is not PluginBase):
                return obj()

        return None

    def register_plugin(self, plugin: PluginBase):
        """手动注册插件"""
        self.plugins[plugin.name] = plugin

    def unload_plugin(self, name: str):
        """卸载插件"""
        if name in self.plugins:
            self.plugins[name].cleanup()
            del self.plugins[name]

    def get_plugin(self, name: str) -> Optional[PluginBase]:
        """获取插件实例"""
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        """列出所有插件"""
        return [
            {
                "name": p.name,
                "description": p.description,
                "version": p.version,
                "author": p.author
            }
            for p in self.plugins.values()
        ]

    def run_plugin(self, name: str, engine: DisasmEngine,
                   target: Any) -> Dict[str, Any]:
        """
        运行插件

        Args:
            name: 插件名
            engine: 反汇编引擎
            target: 分析目标

        Returns:
            分析结果
        """
        plugin = self.plugins.get(name)
        if not plugin:
            return {"error": f"Plugin not found: {name}"}

        plugin.initialize(engine)
        try:
            result = plugin.analyze(target)
            plugin.results = result
            return result
        except Exception as e:
            return {"error": str(e)}

    def run_all(self, engine: DisasmEngine,
                target: Any) -> Dict[str, Dict]:
        """运行所有插件"""
        results = {}
        for name, plugin in self.plugins.items():
            results[name] = self.run_plugin(name, engine, target)
        return results

    def get_all_commands(self) -> Dict[str, callable]:
        """获取所有插件的命令"""
        commands = {}
        for plugin in self.plugins.values():
            cmds = plugin.get_commands()
            for cmd_name, handler in cmds.items():
                # 添加插件前缀避免冲突
                full_name = f"{plugin.name}.{cmd_name}"
                commands[full_name] = handler
        return commands
