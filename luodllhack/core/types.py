# -*- coding: utf-8 -*-
"""
luodllhack/core/types.py - Unified Type Definitions

Consolidates all vulnerability analysis-related data structures, including:
- Vulnerability type enumerations
- Taint analysis data structures
- Memory lifecycle tracking
- Integer overflow detection
- Confidence scoring system
- API definition constants
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from enum import Enum, auto


# =============================================================================
# Base Enumeration Types
# =============================================================================

class VulnType(Enum):
    """Vulnerability Types - Covers modern mainstream vulnerabilities"""
    # Traditional Types
    BUFFER_OVERFLOW = auto()      # CWE-120: Stack/Heap Buffer Overflow
    FORMAT_STRING = auto()        # CWE-134: Format String
    COMMAND_INJECTION = auto()    # CWE-78: Command Injection
    PATH_TRAVERSAL = auto()       # CWE-22: Path Traversal
    INTEGER_OVERFLOW = auto()     # CWE-190: Integer Overflow
    USE_AFTER_FREE = auto()       # CWE-416: Use-After-Free
    DOUBLE_FREE = auto()          # CWE-415: Double-Free
    NULL_DEREFERENCE = auto()     # CWE-476: NULL Pointer Dereference

    # Modern High-Risk Types
    TYPE_CONFUSION = auto()       # CWE-843: Type Confusion
    OUT_OF_BOUNDS_READ = auto()   # CWE-125: Out-of-bounds Read
    OUT_OF_BOUNDS_WRITE = auto()  # CWE-787: Out-of-bounds Write
    HEAP_OVERFLOW = auto()        # CWE-122: Heap Overflow
    INTEGER_UNDERFLOW = auto()    # CWE-191: Integer Underflow
    UNINITIALIZED_MEMORY = auto() # CWE-908: Uninitialized Memory
    RACE_CONDITION = auto()       # CWE-362: Race Condition
    MEMORY_LEAK = auto()          # CWE-401: Memory Leak
    STACK_EXHAUSTION = auto()     # CWE-674: Stack Exhaustion
    DESERIALIZATION = auto()      # CWE-502: Deserialization
    PRIVILEGE_ESCALATION = auto() # CWE-269: Privilege Escalation
    INFO_DISCLOSURE = auto()      # CWE-200: Information Exposure
    CONTROL_FLOW_HIJACK = auto()  # CWE-123: Control Flow Hijacking (Indirect call tainted)
    UNTRUSTED_POINTER_DEREFERENCE = auto()  # CWE-822: Untrusted Pointer Dereference


class SourceType(Enum):
    """Taint Source Types - Covers all external inputs"""
    UNKNOWN = auto()        # Unknown source
    # Traditional Sources
    NETWORK = auto()        # recv, recvfrom, WSARecv
    FILE = auto()           # read, fread, ReadFile
    USER_INPUT = auto()     # gets, scanf
    ARGUMENT = auto()       # Function argument
    ENVIRONMENT = auto()    # getenv
    REGISTRY = auto()       # RegQueryValue

    # Modern Sources
    IPC = auto()            # Inter-Process Communication
    RPC = auto()            # Remote Procedure Call
    CLIPBOARD = auto()      # Clipboard
    DRAG_DROP = auto()      # Drag and Drop
    DATABASE = auto()       # Database
    WEB_REQUEST = auto()    # HTTP/WebSocket
    DESERIALIZED = auto()   # Deserialization
    SHARED_MEMORY = auto()  # Shared Memory
    MESSAGE_QUEUE = auto()  # Message Queue


class PointerState(Enum):
    """Pointer States - Used for UAF/Double-Free detection"""
    UNKNOWN = auto()      # Unknown state
    ALLOCATED = auto()    # Allocated
    FREED = auto()        # Freed
    REALLOCATED = auto()  # Reallocated


class ArithmeticOp(Enum):
    """Arithmetic Operation Types"""
    MUL = auto()      # Multiplication
    IMUL = auto()     # Signed Multiplication
    ADD = auto()      # Addition
    SUB = auto()      # Subtraction
    SHL = auto()      # Shift Left
    UNKNOWN = auto()


class ConfidenceFactor(Enum):
    """Confidence Scoring Factors"""
    # =========================================================================
    # Static Analysis Factors (Total weight 40%)
    # =========================================================================
    TAINT_PATH_EXISTS = "taint_path"           # Taint path exists (15%)
    DANGEROUS_API_CALL = "dangerous_api"       # Dangerous API call (10%)
    USER_INPUT_DIRECT = "user_input"           # User input is controllable (5%)
    NO_BOUNDS_CHECK = "no_bounds"              # Missing bounds check (5%)
    ARITHMETIC_OVERFLOW = "arith_overflow"     # Arithmetic overflow risk (3%)
    INDIRECT_CALL_TAINTED = "indirect_call"    # Indirect call is tainted (2%)
    NO_NULL_CHECK = "no_null"                  # Missing NULL check (2%)
    CROSS_FUNCTION = "cross_func"              # Cross-functional propagation (2%)
    MULTIPLE_PATHS = "multi_path"              # Reachable via multiple paths (1%)

    # =========================================================================
    # Agent Verification Factors (Total weight 60% - Agent dominated)
    # =========================================================================
    # PoC Execution Verification (Weight 30%)
    POC_CRASH_CONTROLLED = "poc_crash_controlled"      # Crash at controlled address (+25%)
    POC_CRASH_UNCONTROLLED = "poc_crash_uncontrolled"  # Crash at uncontrolled address (+10%)
    POC_FUNCTION_ERROR = "poc_func_error"              # Function returns error code (-20%)
    POC_EXECUTION_OK = "poc_exec_ok"                   # Successful execution without crash (+5%)
    POC_TIMEOUT = "poc_timeout"                        # Execution timeout (-5%)

    # Agent Intelligent Adjudication (Weight 30%)
    AI_CONFIRMED = "ai_confirmed"                      # Initial AI confirmation (+10%)
    AGENT_TRUE_POSITIVE = "agent_true_positive"        # Agent determines true positive (+25%)
    AGENT_FALSE_POSITIVE = "agent_false_positive"      # Agent determines false positive (-40%)
    AGENT_NEEDS_REVIEW = "agent_needs_review"          # Needs further manual review (0%)
    LLM_DEEP_VERIFIED = "llm_deep_verified"            # Deep LLM verification passed (+15%)
    LLM_DEEP_REJECTED = "llm_deep_rejected"            # Deep LLM verification rejected (-25%)


# =============================================================================
# Taint Analysis Data Structures
# =============================================================================

@dataclass
class TaintSource:
    """Taint Source"""
    type: SourceType
    addr: int
    api_name: str
    tainted_location: str  # 'reg:rcx' or 'mem:0x1000' or 'ret'


@dataclass
class TaintSink:
    """Dangerous Sink"""
    vuln_type: VulnType
    severity: str
    addr: int
    api_name: str
    tainted_arg_idx: int


@dataclass
class TaintStep:
    """A single step in taint propagation"""
    addr: int
    instruction: str
    effect: str  # 'copy', 'derive', 'store', 'load'
    from_loc: str
    to_loc: str


@dataclass
class TaintPath:
    """A complete taint propagation path"""
    source: TaintSource
    sink: TaintSink
    steps: List[TaintStep] = field(default_factory=list)
    constraints: List[Any] = field(default_factory=list)
    confidence: float = 0.0
    func_name: str = ""
    analysis_notes: List[str] = field(default_factory=list)  # Enhanced analysis notes


@dataclass
class VulnFinding:
    """Vulnerability Discovery result"""
    vuln_type: VulnType
    severity: str
    source: TaintSource
    sink: TaintSink
    taint_path: TaintPath
    trigger_input: Optional[bytes] = None
    poc_code: Optional[str] = None
    poc_path: Optional[str] = None
    harness_code: Optional[str] = None
    harness_path: Optional[str] = None
    cwe_id: Optional[str] = None


# =============================================================================
# Cross-Function Analysis Data Structures
# =============================================================================

@dataclass
class InternalCall:
    """Record of internal function call"""
    call_addr: int
    target_addr: int
    tainted_args: Set[int] = field(default_factory=set)


@dataclass
class FunctionSummary:
    """Function taint summary"""
    func_addr: int
    func_name: str
    tainted_args_to_sink: Dict[int, List[TaintSink]] = field(default_factory=dict)
    args_affect_return: Set[int] = field(default_factory=set)
    internal_sinks: List[TaintSink] = field(default_factory=list)
    called_functions: Set[int] = field(default_factory=set)
    internal_calls: List[InternalCall] = field(default_factory=list)

    # Pointer behavior summary
    frees_params: Set[int] = field(default_factory=set)
    allocates_to_params: Set[int] = field(default_factory=set)
    returns_allocated: bool = False
    stores_params: Dict[int, str] = field(default_factory=dict)
    analyzed: bool = False


@dataclass
class CallGraphNode:
    """Call graph node"""
    addr: int
    name: str
    callees: Set[int] = field(default_factory=set)
    callers: Set[int] = field(default_factory=set)
    is_export: bool = False
    is_import: bool = False


@dataclass
class CrossFunctionPath:
    """Cross-function taint path"""
    entry_func: str
    call_chain: List[str] = field(default_factory=list)
    source: TaintSource = None
    sink: TaintSink = None
    steps: List[TaintStep] = field(default_factory=list)
    confidence: float = 0.0


# =============================================================================
# Memory Lifecycle Tracking
# =============================================================================

@dataclass
class PointerInfo:
    """Pointer Information - tracks heap pointer lifecycle"""
    state: PointerState
    alloc_addr: int
    alloc_api: str
    free_addr: Optional[int] = None
    free_api: Optional[str] = None
    size_tainted: bool = False
    source_reg: Optional[str] = None


@dataclass
class MemoryVulnFinding:
    """Memory Vulnerability Discovery - UAF/Double-Free"""
    vuln_type: VulnType
    severity: str
    alloc_addr: int
    alloc_api: str
    free_addr: int
    free_api: str
    vuln_addr: int
    vuln_action: str
    pointer_reg: str
    call_chain: List[str] = field(default_factory=list)
    cwe_id: str = ""
    func_name: str = ""


@dataclass
class CrossFunctionUAF:
    """Cross-function UAF Discovery"""
    vuln_type: VulnType
    severity: str = "Critical"

    alloc_func: str = ""
    alloc_addr: int = 0
    alloc_api: str = ""

    free_func: str = ""
    free_addr: int = 0
    free_api: str = ""

    use_func: str = ""
    use_addr: int = 0
    use_action: str = ""

    call_chain: List[str] = field(default_factory=list)
    param_index: int = -1
    cwe_id: str = "CWE-416"


@dataclass
class PointerParamState:
    """Tracking of pointer state for function parameters"""
    param_index: int
    state: PointerState
    source_func: str = ""
    alloc_addr: int = 0
    freed_by_func: str = ""
    freed_at_addr: int = 0


# =============================================================================
# Integer Overflow Detection
# =============================================================================

@dataclass
class IntegerOverflowInfo:
    """Integer overflow risk information"""
    operation: ArithmeticOp
    addr: int
    instruction: str
    operand1_tainted: bool = False
    operand2_tainted: bool = False
    operand1_reg: str = ""
    operand2_reg: str = ""
    result_reg: str = ""
    risk_level: str = "Medium"
    source: Optional[TaintSource] = None


@dataclass
class IntegerOverflowFinding:
    """Discovery of Integer Overflow -> Heap Overflow vulnerabilities"""
    vuln_type: VulnType = VulnType.INTEGER_OVERFLOW
    severity: str = "High"
    overflow_addr: int = 0
    overflow_op: str = ""
    overflow_instruction: str = ""
    overflow_operation: Any = None
    alloc_addr: int = 0
    alloc_api: str = ""
    alloc_size_reg: str = ""
    size_reg: str = ""  # Alias for alloc_size_reg to satisfy legacy code
    func_name: str = ""
    call_chain: List[str] = field(default_factory=list)
    path_steps: List[Any] = field(default_factory=list)
    taint_source: str = ""
    risk_level: str = "High"
    cwe_id: str = "CWE-190"


# =============================================================================
# Confidence Scoring System
# =============================================================================

# Scoring weight configuration
CONFIDENCE_WEIGHTS: Dict[ConfidenceFactor, float] = {
    ConfidenceFactor.TAINT_PATH_EXISTS: 0.25,
    ConfidenceFactor.AI_CONFIRMED: 0.20,
    ConfidenceFactor.DANGEROUS_API_CALL: 0.15,
    ConfidenceFactor.USER_INPUT_DIRECT: 0.15,
    ConfidenceFactor.NO_BOUNDS_CHECK: 0.10,
    ConfidenceFactor.ARITHMETIC_OVERFLOW: 0.05,
    ConfidenceFactor.NO_NULL_CHECK: 0.03,
    ConfidenceFactor.CROSS_FUNCTION: 0.04,
    ConfidenceFactor.MULTIPLE_PATHS: 0.03,
}

# Thresholds for confidence levels
CONFIDENCE_LEVELS = {
    "Confirmed": 0.85,
    "High": 0.70,
    "Medium": 0.50,
    "Low": 0.30,
    "Suspicious": 0.0,
}


@dataclass
class ConfidenceScore:
    """Confidence scoring result"""
    total_score: float
    level: str = ""
    factors: Dict[ConfidenceFactor, bool] = field(default_factory=dict)
    factor_contributions: Dict[ConfidenceFactor, float] = field(default_factory=dict)
    explanation: str = ""

    def __post_init__(self) -> None:
        for level, threshold in CONFIDENCE_LEVELS.items():
            if self.total_score >= threshold:
                self.level = level
                break

    def update_level(self) -> None:
        """Update confidence level based on the current total score"""
        for level, threshold in CONFIDENCE_LEVELS.items():
            if self.total_score >= threshold:
                self.level = level
                break


@dataclass
class ScoredFinding:
    """Vulnerability finding accompanied by a confidence score"""
    finding_type: str
    vuln_type: VulnType
    severity: str
    location: int
    func_name: str
    confidence: ConfidenceScore
    raw_finding: Any
    sources: List[str] = field(default_factory=list)
    ai_analysis: Optional[str] = None  # AI analysis suggestion/description
    is_false_positive: bool = False  # Flag for false positive after AI review
    review_reasons: Optional[List[str]] = None  # Reason for false positive designation
    original_finding_id: Optional[str] = None  # Original discovery ID
    poc_path: Optional[str] = None
    harness_path: Optional[str] = None

    def __lt__(self, other) -> bool:
        return self.confidence.total_score > other.confidence.total_score


# =============================================================================
# API Definition Constants
# =============================================================================

# High-risk arithmetic instructions
OVERFLOW_RISK_INSTRUCTIONS = {
    'mul': ArithmeticOp.MUL,
    'imul': ArithmeticOp.IMUL,
    'add': ArithmeticOp.ADD,
    'sub': ArithmeticOp.SUB,
    'shl': ArithmeticOp.SHL,
    'sal': ArithmeticOp.SHL,
}

# Operation risk levels
OVERFLOW_RISK_LEVELS = {
    ArithmeticOp.MUL: "Critical",
    ArithmeticOp.IMUL: "Critical",
    ArithmeticOp.SHL: "High",
    ArithmeticOp.ADD: "Medium",
    ArithmeticOp.SUB: "Medium",
}

# Allocation APIs
ALLOC_APIS: Dict[bytes, Dict] = {
    b'malloc': {'ret_ptr': True, 'size_arg': 0},
    b'calloc': {'ret_ptr': True, 'size_arg': [0, 1]},
    b'realloc': {'ret_ptr': True, 'ptr_arg': 0, 'size_arg': 1},
    b'_aligned_malloc': {'ret_ptr': True, 'size_arg': 0},
    b'HeapAlloc': {'ret_ptr': True, 'size_arg': 2},
    b'HeapReAlloc': {'ret_ptr': True, 'ptr_arg': 2, 'size_arg': 3},
    b'RtlAllocateHeap': {'ret_ptr': True, 'size_arg': 2},
    b'VirtualAlloc': {'ret_ptr': True, 'size_arg': 1},
    b'LocalAlloc': {'ret_ptr': True, 'size_arg': 1},
    b'GlobalAlloc': {'ret_ptr': True, 'size_arg': 1},
    b'CoTaskMemAlloc': {'ret_ptr': True, 'size_arg': 0},
    b'SysAllocString': {'ret_ptr': True},
}

# Deallocation APIs
FREE_APIS: Dict[bytes, Dict] = {
    b'free': {'ptr_arg': 0},
    b'_aligned_free': {'ptr_arg': 0},
    b'HeapFree': {'ptr_arg': 2},
    b'RtlFreeHeap': {'ptr_arg': 2},
    b'VirtualFree': {'ptr_arg': 0},
    b'LocalFree': {'ptr_arg': 0},
    b'GlobalFree': {'ptr_arg': 0},
    b'CoTaskMemFree': {'ptr_arg': 0},
    b'SysFreeString': {'ptr_arg': 0},
}

# Pointer usage APIs
POINTER_USE_APIS: Dict[bytes, Dict] = {
    b'memcpy': {'ptr_args': [0, 1]},
    b'memmove': {'ptr_args': [0, 1]},
    b'memset': {'ptr_args': [0]},
    b'strcpy': {'ptr_args': [0, 1]},
    b'strncpy': {'ptr_args': [0, 1]},
    b'strcat': {'ptr_args': [0, 1]},
    b'strlen': {'ptr_args': [0]},
    b'wcscpy': {'ptr_args': [0, 1]},
    b'wcsncpy': {'ptr_args': [0, 1]},
}

# Taint source definitions
TAINT_SOURCES: Dict[bytes, Dict] = {
    b'recv': {'type': SourceType.NETWORK, 'tainted_ret': True, 'tainted_args': [1]},
    b'recvfrom': {'type': SourceType.NETWORK, 'tainted_ret': True, 'tainted_args': [1]},
    b'ReadFile': {'type': SourceType.FILE, 'tainted_args': [1]},
    b'fread': {'type': SourceType.FILE, 'tainted_args': [0]},
    b'gets': {'type': SourceType.USER_INPUT, 'tainted_args': [0]},
    b'scanf': {'type': SourceType.USER_INPUT, 'tainted_args': [1, 2, 3, 4, 5]},
    b'getenv': {'type': SourceType.ENVIRONMENT, 'tainted_ret': True},
    b'RegQueryValueExA': {'type': SourceType.REGISTRY, 'tainted_args': [4]},
    b'GetClipboardData': {'type': SourceType.CLIPBOARD, 'tainted_ret': True},
}

# Dangerous Sink definitions
DANGEROUS_SINKS: Dict[bytes, Dict] = {
    # Buffer Overflow
    b'strcpy': {'vuln': VulnType.BUFFER_OVERFLOW, 'severity': 'Critical', 'check_args': [1], 'cwe': 'CWE-120'},
    b'strcat': {'vuln': VulnType.BUFFER_OVERFLOW, 'severity': 'Critical', 'check_args': [1], 'cwe': 'CWE-120'},
    b'sprintf': {'vuln': VulnType.BUFFER_OVERFLOW, 'severity': 'Critical', 'check_args': [1], 'cwe': 'CWE-120'},
    b'memcpy': {'vuln': VulnType.BUFFER_OVERFLOW, 'severity': 'High', 'check_args': [1, 2], 'cwe': 'CWE-120'},
    b'gets': {'vuln': VulnType.BUFFER_OVERFLOW, 'severity': 'Critical', 'check_args': [0], 'cwe': 'CWE-242'},
    # Format String
    b'printf': {'vuln': VulnType.FORMAT_STRING, 'severity': 'High', 'check_args': [0], 'cwe': 'CWE-134'},
    b'sprintf': {'vuln': VulnType.FORMAT_STRING, 'severity': 'High', 'check_args': [1], 'cwe': 'CWE-134'},
    # Command Injection
    b'system': {'vuln': VulnType.COMMAND_INJECTION, 'severity': 'Critical', 'check_args': [0], 'cwe': 'CWE-78'},
    b'WinExec': {'vuln': VulnType.COMMAND_INJECTION, 'severity': 'Critical', 'check_args': [0], 'cwe': 'CWE-78'},
    b'CreateProcessA': {'vuln': VulnType.COMMAND_INJECTION, 'severity': 'Critical', 'check_args': [0, 1], 'cwe': 'CWE-78'},
    # Path Traversal
    b'fopen': {'vuln': VulnType.PATH_TRAVERSAL, 'severity': 'High', 'check_args': [0], 'cwe': 'CWE-22'},
    b'CreateFileA': {'vuln': VulnType.PATH_TRAVERSAL, 'severity': 'High', 'check_args': [0], 'cwe': 'CWE-22'},
    b'LoadLibraryA': {'vuln': VulnType.PATH_TRAVERSAL, 'severity': 'Critical', 'check_args': [0], 'cwe': 'CWE-22'},
    # Memory Operations
    b'free': {'vuln': VulnType.DOUBLE_FREE, 'severity': 'Critical', 'check_args': [0], 'cwe': 'CWE-415'},
    b'HeapFree': {'vuln': VulnType.DOUBLE_FREE, 'severity': 'Critical', 'check_args': [2], 'cwe': 'CWE-415'},
}
