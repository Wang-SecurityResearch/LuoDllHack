# -*- coding: utf-8 -*-
"""
luodllhack/analysis/plugins/base.py - Analysis Plugin Base Class

Plugin Development Guide:
1. Inherit from the AnalysisPlugin class.
2. Implement the on_instruction() and/or on_function() methods.
3. Place in the plugins/ directory for automatic loading.

Example:
    class MyPlugin(AnalysisPlugin):
        name = "my_detector"
        description = "Detects custom patterns"

        def on_instruction(self, insn, ctx):
            if insn.mnemonic == 'call':
                return [Finding(type=FindingType.SUSPICIOUS, ...)]
            return []
"""

import importlib
import importlib.util
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Callable


class FindingType(Enum):
    """Finding Type"""
    DANGEROUS_CALL = auto()      # Dangerous function call
    NO_BOUNDS_CHECK = auto()     # Missing bounds check
    INDIRECT_CALL = auto()       # Indirect call
    TAINT_SINK = auto()          # Taint reached sink
    SUSPICIOUS_PATTERN = auto()  # Suspicious pattern
    INFO = auto()                # Informational discovery


@dataclass
class Finding:
    """Plugin Finding Result"""
    type: FindingType
    address: int
    description: str
    confidence: float = 0.5      # 0.0 - 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    plugin_name: str = ""

    def __post_init__(self):
        if self.confidence < 0:
            self.confidence = 0.0
        if self.confidence > 1:
            self.confidence = 1.0


@dataclass
class PluginContext:
    """Plugin Execution Context"""
    # Basic information
    binary_path: Path
    arch: str                    # "x86" or "x64"
    image_base: int

    # Current analysis state
    current_function: Optional[str] = None
    current_function_addr: Optional[int] = None

    # Cached data
    imports: Dict[int, str] = field(default_factory=dict)
    exports: Dict[int, str] = field(default_factory=dict)
    strings: Dict[int, str] = field(default_factory=dict)

    # Taint state (if any)
    tainted_regs: Set[str] = field(default_factory=set)
    tainted_mem: Set[int] = field(default_factory=set)

    # Custom data (shared between plugins)
    custom_data: Dict[str, Any] = field(default_factory=dict)


class AnalysisPlugin(ABC):
    """
    Analysis Plugin Base Class

    All analysis plugins must inherit from this class and implement the corresponding callback methods.

    Callback Methods:
        on_instruction(insn, ctx) - Triggered for every instruction.
        on_call(insn, target, api_name, ctx) - Triggered for call instructions.
        on_function_start(func_addr, func_name, ctx) - Triggered at function start.
        on_function_end(func_addr, func_name, findings, ctx) - Triggered at function end.
    """

    # Plugin metadata
    name: str = "base_plugin"
    description: str = "Base analysis plugin"
    version: str = "1.0"
    author: str = "Unknown"

    # Plugin configuration
    enabled: bool = True
    priority: int = 50           # 0-100, higher priority executes first

    def __init__(self):
        self._findings: List[Finding] = []

    def on_instruction(self, insn: Any, ctx: PluginContext) -> List[Finding]:
        """
        Instruction Callback - Triggered for every instruction

        Args:
            insn: Capstone instruction object (or compatible object)
                  - insn.address: int
                  - insn.mnemonic: str
                  - insn.op_str: str
                  - insn.operands: list
            ctx: Plugin context

        Returns:
            List of findings
        """
        return []

    def on_call(self, insn: Any, target: Optional[int],
                api_name: Optional[str], ctx: PluginContext) -> List[Finding]:
        """
        Call Instruction Callback - Triggered for call instructions

        Args:
            insn: Call instruction
            target: Call target address (None for indirect calls)
            api_name: API name (if resolvable)
            ctx: Plugin context

        Returns:
            List of findings
        """
        return []

    def on_function_start(self, func_addr: int, func_name: str,
                          ctx: PluginContext) -> None:
        """Function analysis start callback"""
        pass

    def on_function_end(self, func_addr: int, func_name: str,
                        findings: List[Finding], ctx: PluginContext) -> List[Finding]:
        """
        Function analysis end callback

        Can be used for function-level aggregate analysis.

        Args:
            func_addr: Function address
            func_name: Function name
            findings: All findings collected within this function
            ctx: Plugin context

        Returns:
            Can return additional findings (or a modified list of findings)
        """
        return []

    def initialize(self, ctx: PluginContext) -> None:
        """Plugin initialization (called before analysis starts)"""
        pass

    def cleanup(self) -> None:
        """Clean up resources"""
        self._findings.clear()

    def get_config_schema(self) -> Dict[str, Any]:
        """Returns the plugin configuration schema (for validation)"""
        return {}

    def configure(self, config: Dict[str, Any]) -> None:
        """Applies configuration"""
        pass


class PluginManager:
    """
    Plugin Manager

    Responsible for loading, managing, and executing analysis plugins.

    Usage:
        manager = PluginManager()
        manager.load_plugins()  # Load plugin directory

        # In analysis loop
        ctx = PluginContext(...)
        for insn in instructions:
            findings = manager.on_instruction(insn, ctx)
    """

    def __init__(self, plugin_dir: Path = None):
        self.plugin_dir = plugin_dir or Path(__file__).parent
        self.plugins: Dict[str, AnalysisPlugin] = {}
        self._sorted_plugins: List[AnalysisPlugin] = []
        self.loaded = False

    def load_plugins(self) -> List[str]:
        """
        Load all plugins

        Returns:
            List of loaded plugin names
        """
        loaded = []

        # Load built-in plugins
        self._load_builtin_plugins()

        # Load external plugins
        for file in self.plugin_dir.glob("*.py"):
            if file.name.startswith("_") or file.name == "base.py":
                continue

            try:
                plugins = self._load_plugin_file(file)
                for plugin in plugins:
                    if plugin.enabled:
                        self.plugins[plugin.name] = plugin
                        loaded.append(plugin.name)
            except Exception as e:
                print(f"[!] Failed to load plugin {file.name}: {e}")

        # Sort by priority
        self._sorted_plugins = sorted(
            self.plugins.values(),
            key=lambda p: p.priority,
            reverse=True
        )

        self.loaded = True
        return loaded

    def _load_builtin_plugins(self):
        """Load built-in plugins"""
        try:
            from .builtin import get_builtin_plugins
            for plugin in get_builtin_plugins():
                if plugin.enabled:
                    self.plugins[plugin.name] = plugin
        except ImportError:
            pass  # Built-in plugins are optional

    def _load_plugin_file(self, path: Path) -> List[AnalysisPlugin]:
        """Load plugins from file (supports multiple plugins per file)"""
        import sys

        # Ensure parent package is in sys.path
        parent_dir = str(path.parent.parent.parent.parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)

        module_name = f"luodllhack.analysis.plugins.{path.stem}"

        try:
            module = importlib.import_module(module_name)
        except ImportError:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            if not spec or not spec.loader:
                return []
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

        # Find all AnalysisPlugin subclasses (excluding base classes themselves)
        plugins = []
        base_classes = {AnalysisPlugin, TaintDefinitionPlugin, MemoryLifecyclePlugin}

        for name in dir(module):
            obj = getattr(module, name)
            if (isinstance(obj, type) and
                issubclass(obj, AnalysisPlugin) and
                obj not in base_classes):
                try:
                    plugins.append(obj())
                except Exception as e:
                    print(f"[!] Failed to instantiate plugin {name}: {e}")

        return plugins

    def register_plugin(self, plugin: AnalysisPlugin) -> None:
        """Manually register a plugin"""
        self.plugins[plugin.name] = plugin
        self._sorted_plugins = sorted(
            self.plugins.values(),
            key=lambda p: p.priority,
            reverse=True
        )

    def unload_plugin(self, name: str) -> None:
        """Unload a plugin"""
        if name in self.plugins:
            self.plugins[name].cleanup()
            del self.plugins[name]
            self._sorted_plugins = [p for p in self._sorted_plugins if p.name != name]

    def get_plugin(self, name: str) -> Optional[AnalysisPlugin]:
        """Get plugin instance"""
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        """List all plugins"""
        return [
            {
                "name": p.name,
                "description": p.description,
                "version": p.version,
                "priority": p.priority,
                "enabled": p.enabled
            }
            for p in self._sorted_plugins
        ]

    def initialize_all(self, ctx: PluginContext) -> None:
        """Initialize all plugins"""
        for plugin in self._sorted_plugins:
            try:
                plugin.initialize(ctx)
            except Exception as e:
                print(f"[!] Plugin initialization failed {plugin.name}: {e}")

    def on_instruction(self, insn: Any, ctx: PluginContext) -> List[Finding]:
        """
        Trigger instruction callbacks for all plugins

        Args:
            insn: Capstone instruction object
            ctx: Plugin context

        Returns:
            Merged list of findings from all plugins
        """
        all_findings = []

        for plugin in self._sorted_plugins:
            try:
                findings = plugin.on_instruction(insn, ctx)
                for f in findings:
                    f.plugin_name = plugin.name
                all_findings.extend(findings)
            except Exception as e:
                print(f"[!] Plugin execution failed {plugin.name}.on_instruction: {e}")

        return all_findings

    def on_call(self, insn: Any, target: Optional[int],
                api_name: Optional[str], ctx: PluginContext) -> List[Finding]:
        """Trigger call callbacks for all plugins"""
        all_findings = []

        for plugin in self._sorted_plugins:
            try:
                findings = plugin.on_call(insn, target, api_name, ctx)
                for f in findings:
                    f.plugin_name = plugin.name
                all_findings.extend(findings)
            except Exception as e:
                print(f"[!] Plugin execution failed {plugin.name}.on_call: {e}")

        return all_findings

    def on_function_start(self, func_addr: int, func_name: str,
                          ctx: PluginContext) -> None:
        """Trigger function start callbacks for all plugins"""
        for plugin in self._sorted_plugins:
            try:
                plugin.on_function_start(func_addr, func_name, ctx)
            except Exception as e:
                print(f"[!] Plugin execution failed {plugin.name}.on_function_start: {e}")

    def on_function_end(self, func_addr: int, func_name: str,
                        findings: List[Finding], ctx: PluginContext) -> List[Finding]:
        """Trigger function end callbacks for all plugins"""
        all_new_findings = []

        for plugin in self._sorted_plugins:
            try:
                new_findings = plugin.on_function_end(func_addr, func_name, findings, ctx)
                for f in new_findings:
                    f.plugin_name = plugin.name
                all_new_findings.extend(new_findings)
            except Exception as e:
                print(f"[!] Plugin execution failed {plugin.name}.on_function_end: {e}")

        return all_new_findings

    def cleanup_all(self) -> None:
        """Clean up all plugins"""
        for plugin in self._sorted_plugins:
            try:
                plugin.cleanup()
            except Exception:
                pass

    def get_taint_sources(self) -> Dict[str, Dict[str, Any]]:
        """Collect taint source definitions from all plugins"""
        sources = {}
        for plugin in self._sorted_plugins:
            if isinstance(plugin, TaintDefinitionPlugin):
                sources.update(plugin.get_taint_sources())
        return sources

    def get_taint_sinks(self) -> Dict[str, Dict[str, Any]]:
        """Collect taint sink definitions from all plugins"""
        sinks = {}
        for plugin in self._sorted_plugins:
            if isinstance(plugin, TaintDefinitionPlugin):
                sinks.update(plugin.get_taint_sinks())
        return sinks


# =============================================================================
# Taint Source/Sink Definition Plugin
# =============================================================================

class TaintDefinitionPlugin(AnalysisPlugin):
    """
    Taint Source/Sink Definition Plugin Base Class

    Used to extend TaintEngine's taint sources and dangerous API definitions.

    Example:
        class MyTaintPlugin(TaintDefinitionPlugin):
            name = "my_taint_defs"

            def get_taint_sources(self):
                return {
                    "MyCustomAPI": {
                        "type": "custom",
                        "tainted_ret": True,
                        "description": "Custom input source"
                    }
                }

            def get_taint_sinks(self):
                return {
                    "MyDangerousAPI": {
                        "vuln_type": "BUFFER_OVERFLOW",
                        "severity": "high",
                        "sink_args": [0, 1],
                        "description": "Custom dangerous function"
                    }
                }
    """

    name = "taint_definition_plugin"
    description = "Taint Source/Sink Definition Plugin"

    def get_taint_sources(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns taint source definitions

        Returns:
            {api_name: {type, tainted_ret, tainted_args, description, ...}}
        """
        return {}

    def get_taint_sinks(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns taint sink (dangerous API) definitions

        Returns:
            {api_name: {vuln_type, severity, sink_args, description, ...}}
        """
        return {}

    def on_instruction(self, insn: Any, ctx: PluginContext) -> List[Finding]:
        # Definition-type plugins usually don't need instruction callbacks
        return []


# =============================================================================
# Memory Lifecycle Plugin
# =============================================================================

class MemoryLifecyclePlugin(AnalysisPlugin):
    """
    Memory Lifecycle Tracking Plugin Base Class

    Used for custom detection rules for memory vulnerabilities such as UAF/Double-Free.

    Example:
        class MyMemoryPlugin(MemoryLifecyclePlugin):
            name = "my_memory_tracker"

            def get_alloc_apis(self):
                return {
                    "MyAlloc": {"returns_ptr": True},
                    "MyPoolAlloc": {"returns_ptr": True, "size_arg": 0}
                }

            def get_free_apis(self):
                return {
                    "MyFree": {"ptr_arg": 0},
                    "MyPoolFree": {"ptr_arg": 1}
                }
    """

    name = "memory_lifecycle_plugin"
    description = "Memory Lifecycle Tracking Plugin"

    def get_alloc_apis(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns memory allocation API definitions

        Returns:
            {api_name: {returns_ptr, size_arg, ...}}
        """
        return {}

    def get_free_apis(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns memory deallocation API definitions

        Returns:
            {api_name: {ptr_arg, ...}}
        """
        return {}

    def on_instruction(self, insn: Any, ctx: PluginContext) -> List[Finding]:
        return []
