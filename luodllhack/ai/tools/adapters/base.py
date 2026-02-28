# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/adapters/base.py
MCP Style Tool Base Classes

Provides standardized tool definition and registration mechanisms.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Type, Union

logger = logging.getLogger(__name__)


# =============================================================================
# Tool Schema
# =============================================================================

@dataclass
class MCPToolSchema:
    """
    MCP style tool Schema

    Defines the tool name, description, and parameters.
    Compatible with OpenAI Function Calling and Anthropic Tool Use.
    """
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema format
    required: List[str] = field(default_factory=list)
    returns: Optional[Dict[str, Any]] = None  # Return value schema

    def to_openai_function(self) -> Dict[str, Any]:
        """Convert to OpenAI Function Calling format"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": self.parameters,
                "required": self.required,
            }
        }

    def to_anthropic_tool(self) -> Dict[str, Any]:
        """Convert to Anthropic Tool Use format"""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.parameters,
                "required": self.required,
            }
        }

    def to_gemini_function(self) -> Dict[str, Any]:
        """Convert to Gemini Function Calling format"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": self.parameters,
                "required": self.required,
            }
        }


# =============================================================================
# Tool Results
# =============================================================================

class MCPResultStatus(str, Enum):
    """Result status"""
    SUCCESS = "success"
    ERROR = "error"
    PARTIAL = "partial"
    TIMEOUT = "timeout"


@dataclass
class MCPToolResult:
    """
    MCP tool execution result
    """
    tool_name: str
    status: MCPResultStatus
    data: Optional[Any] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.status == MCPResultStatus.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "status": self.status.value,
            "data": self.data,
            "error": self.error,
            "execution_time": self.execution_time,
            "metadata": self.metadata,
        }

    @classmethod
    def success_result(cls, tool_name: str, data: Any, execution_time: float = 0.0) -> "MCPToolResult":
        return cls(
            tool_name=tool_name,
            status=MCPResultStatus.SUCCESS,
            data=data,
            execution_time=execution_time,
        )

    @classmethod
    def error_result(cls, tool_name: str, error: str, execution_time: float = 0.0) -> "MCPToolResult":
        return cls(
            tool_name=tool_name,
            status=MCPResultStatus.ERROR,
            error=error,
            execution_time=execution_time,
        )


# =============================================================================
# MCP Tool Base Class
# =============================================================================

class MCPTool(ABC):
    """
    MCP style tool base class

    Subclasses must implement:
    - name: Tool name
    - description: Tool description
    - parameters: Parameter definition
    - execute: Execution logic
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Tool description"""
        pass

    @property
    @abstractmethod
    def parameters(self) -> Dict[str, Any]:
        """Parameter definition (JSON Schema)"""
        pass

    @property
    def required_params(self) -> List[str]:
        """Required parameters"""
        return []

    @abstractmethod
    def execute(self, **kwargs) -> Any:
        """
        Execute tool

        Args:
            **kwargs: Tool parameters

        Returns:
            Execution result
        """
        pass

    def get_schema(self) -> MCPToolSchema:
        """Get tool Schema"""
        return MCPToolSchema(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
            required=self.required_params,
        )

    def __call__(self, **kwargs) -> MCPToolResult:
        """Call tool"""
        start_time = time.time()
        try:
            result = self.execute(**kwargs)
            return MCPToolResult.success_result(
                self.name, result, time.time() - start_time
            )
        except Exception as e:
            logger.error(f"Tool {self.name} failed: {e}")
            return MCPToolResult.error_result(
                self.name, str(e), time.time() - start_time
            )


# =============================================================================
# MCP Tool Registry
# =============================================================================

class MCPToolRegistry:
    """
    MCP style tool registry

    Manages all available tools, providing:
    - Tool registration
    - Tool invocation
    - Schema export
    """

    def __init__(self):
        self._tools: Dict[str, MCPTool] = {}
        self._tool_funcs: Dict[str, Callable] = {}

    def register(self, tool: Union[MCPTool, Callable], name: str = None, description: str = None, parameters: Dict = None) -> None:
        """
        Register tool

        Args:
            tool: Tool instance or function
            name: Tool name (required during function registration)
            description: Tool description (required during function registration)
            parameters: Parameter definition (required during function registration)
        """
        if isinstance(tool, MCPTool):
            self._tools[tool.name] = tool
            logger.debug(f"Registered MCP tool: {tool.name}")
        elif callable(tool):
            if not name:
                name = tool.__name__
            self._tool_funcs[name] = tool
            # Create wrapper
            wrapper = _FunctionToolWrapper(name, description or "", parameters or {}, tool)
            self._tools[name] = wrapper
            logger.debug(f"Registered function as MCP tool: {name}")
        else:
            raise TypeError(f"Cannot register {type(tool)} as MCP tool")

    def register_adapter(self, adapter: "MCPToolAdapter") -> None:
        """
        Register tool adapter (batch registration)

        Args:
            adapter: Tool adapter
        """
        for tool in adapter.get_tools():
            self.register(tool)

    def unregister(self, name: str) -> None:
        """Unregister tool"""
        self._tools.pop(name, None)
        self._tool_funcs.pop(name, None)

    def get_tool(self, name: str) -> Optional[MCPTool]:
        """Get tool"""
        return self._tools.get(name)

    def has_tool(self, name: str) -> bool:
        """Check if tool exists"""
        return name in self._tools

    def list_tools(self) -> List[str]:
        """List all tool names"""
        return list(self._tools.keys())

    def call_tool(self, name: str, arguments: Dict[str, Any] = None) -> MCPToolResult:
        """
        Invoke tool

        Args:
            name: Tool name
            arguments: Parameters

        Returns:
            Execution result
        """
        tool = self._tools.get(name)
        if not tool:
            return MCPToolResult.error_result(name, f"Unknown tool: {name}")

        arguments = arguments or {}
        return tool(**arguments)

    def get_schemas(self) -> List[MCPToolSchema]:
        """Get all tool Schemas"""
        return [tool.get_schema() for tool in self._tools.values()]

    def to_openai_functions(self) -> List[Dict[str, Any]]:
        """Export as OpenAI Function Calling format"""
        return [schema.to_openai_function() for schema in self.get_schemas()]

    def to_anthropic_tools(self) -> List[Dict[str, Any]]:
        """Export as Anthropic Tool Use format"""
        return [schema.to_anthropic_tool() for schema in self.get_schemas()]

    def to_gemini_functions(self) -> List[Dict[str, Any]]:
        """Export as Gemini Function Calling format"""
        return [{"function_declarations": [schema.to_gemini_function() for schema in self.get_schemas()]}]


class _FunctionToolWrapper(MCPTool):
    """Function wrapper"""

    def __init__(self, name: str, description: str, parameters: Dict, func: Callable):
        self._name = name
        self._description = description
        self._parameters = parameters
        self._func = func

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def parameters(self) -> Dict[str, Any]:
        return self._parameters

    def execute(self, **kwargs) -> Any:
        return self._func(**kwargs)


# =============================================================================
# MCP Tool Adapter Base Class
# =============================================================================

class MCPToolAdapter(ABC):
    """
    MCP tool adapter base class

    Wraps existing functional modules as a collection of MCP tools.
    """

    @abstractmethod
    def get_tools(self) -> List[MCPTool]:
        """
        Get all tools

        Returns:
            Tool list
        """
        pass

    def get_tool_names(self) -> List[str]:
        """Get all tool names"""
        return [t.name for t in self.get_tools()]
