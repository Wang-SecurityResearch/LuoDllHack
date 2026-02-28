# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/types.py
Base type definitions for the tool system
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ToolResultType(Enum):
    """Tool execution result type"""
    SUCCESS = "success"
    ERROR = "error"
    NO_RESULT = "no_result"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"


@dataclass
class ToolResult:
    """Tool call result"""
    tool_name: str
    status: ToolResultType
    data: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "data": self.data,
            "error": self.error,
            "execution_time": self.execution_time
        }

    @property
    def success(self) -> bool:
        """Whether the call was successful"""
        return self.status == ToolResultType.SUCCESS


@dataclass
class ToolDefinition:
    """Tool definition"""
    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Any = None  # Callable

    def to_declaration(self) -> Dict[str, Any]:
        """Convert to declaration format usable by LLM"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters
        }


@dataclass
class AlgorithmFindings:
    """Storage for algorithm analysis results"""
    taint_paths: List[Any] = field(default_factory=list)
    memory_vulns: List[Any] = field(default_factory=list)
    integer_overflows: List[Any] = field(default_factory=list)
    cross_function_uaf: List[Any] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "taint_paths": self.taint_paths,
            "memory_vulns": self.memory_vulns,
            "integer_overflows": self.integer_overflows,
            "cross_function_uaf": self.cross_function_uaf,
            "summary": self.summary
        }


# =============================================================================
# Agent State Types
# =============================================================================

@dataclass
class AgentState:
    """Agent running state"""
    current_step: int = 0
    max_steps: int = 50
    observations: List[str] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    should_stop: bool = False
    token_budget: int = 80000
    token_used: int = 0


@dataclass
class VulnReport:
    """Structured vulnerability report"""
    risk_level: str = "Low"  # Critical, High, Medium, Low
    exploitability: str = "Hard"  # Easy, Medium, Hard
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    poc_code: Optional[str] = None
    poc_verified: bool = False
    recommendations: List[str] = field(default_factory=list)
    analysis_trace: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "risk_level": self.risk_level,
            "exploitability": self.exploitability,
            "vulnerabilities": self.vulnerabilities,
            "attack_vectors": self.attack_vectors,
            "poc_code": self.poc_code,
            "poc_verified": self.poc_verified,
            "recommendations": self.recommendations,
            "analysis_trace": self.analysis_trace
        }
