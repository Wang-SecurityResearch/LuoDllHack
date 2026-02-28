# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/callback.py

Callback Function Analysis - Phase 2.2

Core Capabilities:
    1. Identify callback function registrations
    2. Track callback function address sources
    3. Analyze parameters passed when callbacks are invoked
    4. Detect safety risks related to callbacks

Callback Types:
    - Windows Hook: SetWindowsHookEx
    - Thread Callbacks: CreateThread, QueueUserWorkItem
    - Timer Callbacks: SetTimer, CreateTimerQueueTimer
    - Enumeration Callbacks: EnumWindows, EnumProcesses
    - Async IO Callbacks: ReadFileEx, WriteFileEx
    - COM Callbacks: Interfaces returned by QueryInterface

Attack Surface:
    - Callback function pointer overwritten by taint → Code execution
    - Callback parameters from untrusted sources → Various injections
    - Callback execution timing exploited → Race conditions
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple, Any
from enum import Enum, auto


class CallbackType(Enum):
    """Callback Type"""
    WINDOW_HOOK = auto()       # Windows message hook
    THREAD_START = auto()      # Thread entry point
    TIMER = auto()             # Timer callback
    ENUM_CALLBACK = auto()     # Enumeration callback
    ASYNC_IO = auto()          # Async IO completion callback
    APC = auto()               # Asynchronous Procedure Call
    COM_INTERFACE = auto()     # COM interface method
    EXCEPTION_HANDLER = auto() # Exception handler function
    ATEXIT = auto()            # Exit callback
    TLS_CALLBACK = auto()      # TLS callback
    UNKNOWN = auto()


@dataclass
class CallbackRegistration:
    """Callback Registration Information"""
    addr: int                      # Address of the registration call
    callback_type: CallbackType
    api_name: str                  # Name of the registration API
    callback_arg_index: int        # Position of the callback parameter
    callback_addr: Optional[int]   # Address of the callback function (if known)
    # Taint analysis
    is_callback_tainted: bool = False
    is_userdata_tainted: bool = False
    taint_source: Optional[str] = None
    # Analysis
    risk_level: str = "Medium"
    risk_reason: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'addr': f'0x{self.addr:x}',
            'type': self.callback_type.name,
            'api': self.api_name,
            'callback_addr': f'0x{self.callback_addr:x}' if self.callback_addr else None,
            'callback_tainted': self.is_callback_tainted,
            'userdata_tainted': self.is_userdata_tainted,
            'risk_level': self.risk_level,
            'risk_reason': self.risk_reason
        }


@dataclass
class CallbackAnalysisResult:
    """Callback Analysis Result"""
    function_addr: int
    registrations: List[CallbackRegistration]
    high_risk_count: int = 0
    tainted_callbacks: int = 0
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            'function': f'0x{self.function_addr:x}',
            'total_callbacks': len(self.registrations),
            'high_risk': self.high_risk_count,
            'tainted': self.tainted_callbacks,
            'summary': self.summary,
            'details': [r.to_dict() for r in self.registrations]
        }


class CallbackAnalyzer:
    """
    Callback Function Analyzer

    Usage:
        analyzer = CallbackAnalyzer(binary_data, image_base, import_map)

        # Analyze callback registrations in a function
        result = analyzer.analyze_function(
            func_addr=0x1000,
            tainted_regs={'rcx', 'rdx'}
        )

        for reg in result.registrations:
            if reg.is_callback_tainted:
                print(f"Danger! Callback function pointer controllable @ 0x{reg.addr:x}")
    """

    # Callback registration API database
    CALLBACK_APIS: Dict[bytes, Dict[str, Any]] = {
        # Windows Hook
        b'SetWindowsHookExA': {
            'type': CallbackType.WINDOW_HOOK,
            'callback_arg': 2,      # lpfn
            'userdata_arg': None,
            'risk_if_tainted': 'Critical',
            'notes': 'Message hook; can intercept system messages'
        },
        b'SetWindowsHookExW': {
            'type': CallbackType.WINDOW_HOOK,
            'callback_arg': 2,
            'userdata_arg': None,
            'risk_if_tainted': 'Critical',
        },

        # Thread
        b'CreateThread': {
            'type': CallbackType.THREAD_START,
            'callback_arg': 2,      # lpStartAddress
            'userdata_arg': 3,      # lpParameter
            'risk_if_tainted': 'Critical',
            'notes': 'Thread entry point; direct code execution'
        },
        b'_beginthread': {
            'type': CallbackType.THREAD_START,
            'callback_arg': 0,
            'userdata_arg': 2,
            'risk_if_tainted': 'Critical',
        },
        b'_beginthreadex': {
            'type': CallbackType.THREAD_START,
            'callback_arg': 2,
            'userdata_arg': 3,
            'risk_if_tainted': 'Critical',
        },
        b'QueueUserWorkItem': {
            'type': CallbackType.THREAD_START,
            'callback_arg': 0,      # Function
            'userdata_arg': 1,      # Context
            'risk_if_tainted': 'Critical',
        },

        # Timer
        b'SetTimer': {
            'type': CallbackType.TIMER,
            'callback_arg': 3,      # lpTimerFunc
            'userdata_arg': None,
            'risk_if_tainted': 'High',
        },
        b'CreateTimerQueueTimer': {
            'type': CallbackType.TIMER,
            'callback_arg': 2,      # Callback
            'userdata_arg': 3,      # Parameter
            'risk_if_tainted': 'High',
        },
        b'timeSetEvent': {
            'type': CallbackType.TIMER,
            'callback_arg': 3,      # lpTimeProc
            'userdata_arg': 4,      # dwUser
            'risk_if_tainted': 'High',
        },

        # Enumeration Callbacks
        b'EnumWindows': {
            'type': CallbackType.ENUM_CALLBACK,
            'callback_arg': 0,      # lpEnumFunc
            'userdata_arg': 1,      # lParam
            'risk_if_tainted': 'High',
        },
        b'EnumChildWindows': {
            'type': CallbackType.ENUM_CALLBACK,
            'callback_arg': 1,
            'userdata_arg': 2,
            'risk_if_tainted': 'High',
        },
        b'EnumDesktopWindows': {
            'type': CallbackType.ENUM_CALLBACK,
            'callback_arg': 1,
            'userdata_arg': 2,
            'risk_if_tainted': 'High',
        },
        b'EnumProcesses': {
            'type': CallbackType.ENUM_CALLBACK,
            'callback_arg': None,   # No callback used
            'userdata_arg': None,
            'risk_if_tainted': 'Low',
        },

        # Async IO
        b'ReadFileEx': {
            'type': CallbackType.ASYNC_IO,
            'callback_arg': 4,      # lpCompletionRoutine
            'userdata_arg': None,
            'risk_if_tainted': 'High',
        },
        b'WriteFileEx': {
            'type': CallbackType.ASYNC_IO,
            'callback_arg': 4,
            'userdata_arg': None,
            'risk_if_tainted': 'High',
        },

        # APC
        b'QueueUserAPC': {
            'type': CallbackType.APC,
            'callback_arg': 0,      # pfnAPC
            'userdata_arg': 2,      # dwData
            'risk_if_tainted': 'Critical',
            'notes': 'Common APC injection method'
        },

        # Wait Callbacks
        b'RegisterWaitForSingleObject': {
            'type': CallbackType.ASYNC_IO,
            'callback_arg': 2,      # Callback
            'userdata_arg': 3,      # Context
            'risk_if_tainted': 'High',
        },

        # Exception Handlers
        b'SetUnhandledExceptionFilter': {
            'type': CallbackType.EXCEPTION_HANDLER,
            'callback_arg': 0,
            'userdata_arg': None,
            'risk_if_tainted': 'Critical',
            'notes': 'Can be used for exception handler hijacking'
        },
        b'AddVectoredExceptionHandler': {
            'type': CallbackType.EXCEPTION_HANDLER,
            'callback_arg': 1,
            'userdata_arg': None,
            'risk_if_tainted': 'Critical',
        },

        # Exit Callbacks
        b'atexit': {
            'type': CallbackType.ATEXIT,
            'callback_arg': 0,
            'userdata_arg': None,
            'risk_if_tainted': 'High',
        },
        b'_onexit': {
            'type': CallbackType.ATEXIT,
            'callback_arg': 0,
            'userdata_arg': None,
            'risk_if_tainted': 'High',
        },
    }

    def __init__(self, binary_data: bytes, image_base: int,
                 import_map: Dict[int, bytes] = None,
                 arch: str = "x64"):
        """
        Initialize the callback analyzer

        Args:
            binary_data: Binary data
            image_base: Image base address
            import_map: Import map {addr: api_name}
            arch: Architecture
        """
        self.binary_data = binary_data
        self.image_base = image_base
        self.import_map = import_map or {}
        self.arch = arch

        # x64 parameter registers
        if arch == "x64":
            self.arg_regs = ['rcx', 'rdx', 'r8', 'r9']
        else:
            self.arg_regs = []  # x86 uses stack

        self.registrations: List[CallbackRegistration] = []

    def analyze_function(self, func_addr: int,
                          tainted_regs: Set[str] = None,
                          call_trace: List[Dict] = None) -> CallbackAnalysisResult:
        """
        Analyze callback registrations within a function

        Args:
            func_addr: Function address
            tainted_regs: Tainted registers
            call_trace: API call trace [{api, addr, args}, ...]

        Returns:
            CallbackAnalysisResult
        """
        tainted_regs = tainted_regs or set()
        self.registrations = []

        # Analyze from call trace
        if call_trace:
            for call in call_trace:
                api_name = call.get('api', b'')
                addr = call.get('addr', 0)
                args = call.get('args', {})

                reg = self._analyze_callback_api(
                    api_name, addr, args, tainted_regs
                )
                if reg:
                    self.registrations.append(reg)

        # Stats
        high_risk = sum(1 for r in self.registrations
                        if r.risk_level in ('Critical', 'High'))
        tainted = sum(1 for r in self.registrations
                      if r.is_callback_tainted)

        summary = self._generate_summary()

        return CallbackAnalysisResult(
            function_addr=func_addr,
            registrations=self.registrations,
            high_risk_count=high_risk,
            tainted_callbacks=tainted,
            summary=summary
        )

    def _analyze_callback_api(self, api_name: bytes, addr: int,
                               args: Dict, tainted_regs: Set[str]) -> Optional[CallbackRegistration]:
        """Analyze a single callback API call"""
        if api_name not in self.CALLBACK_APIS:
            return None

        info = self.CALLBACK_APIS[api_name]
        callback_arg = info.get('callback_arg')
        userdata_arg = info.get('userdata_arg')

        if callback_arg is None:
            return None

        # Check if callback parameter is tainted
        is_callback_tainted = False
        if callback_arg < len(self.arg_regs):
            cb_reg = self.arg_regs[callback_arg]
            is_callback_tainted = cb_reg in tainted_regs

        # Check user-data parameter
        is_userdata_tainted = False
        if userdata_arg is not None and userdata_arg < len(self.arg_regs):
            ud_reg = self.arg_regs[userdata_arg]
            is_userdata_tainted = ud_reg in tainted_regs

        # Determine risk level
        if is_callback_tainted:
            risk_level = info.get('risk_if_tainted', 'High')
            risk_reason = "Callback function pointer controllable by tainted data"
        elif is_userdata_tainted:
            risk_level = "Medium"
            risk_reason = "Callback user-data parameter is tainted"
        else:
            risk_level = "Low"
            risk_reason = "Callback registration; parameters not tainted"

        return CallbackRegistration(
            addr=addr,
            callback_type=info['type'],
            api_name=api_name.decode(),
            callback_arg_index=callback_arg,
            callback_addr=args.get(f'arg{callback_arg}'),
            is_callback_tainted=is_callback_tainted,
            is_userdata_tainted=is_userdata_tainted,
            risk_level=risk_level,
            risk_reason=risk_reason,
            notes=[info.get('notes', '')]
        )

    def _generate_summary(self) -> str:
        """Generate analysis summary"""
        if not self.registrations:
            return "No callback registrations found"

        critical = sum(1 for r in self.registrations if r.risk_level == 'Critical')
        high = sum(1 for r in self.registrations if r.risk_level == 'High')
        tainted = sum(1 for r in self.registrations if r.is_callback_tainted)

        parts = [f"Found {len(self.registrations)} callback registrations"]

        if critical > 0:
            parts.append(f"{critical} critical risks")
        if high > 0:
            parts.append(f"{high} high risks")
        if tainted > 0:
            parts.append(f"{tainted} callback pointers controllable")

        return ", ".join(parts)

    def check_api_call(self, api_name: bytes, addr: int,
                        tainted_args: List[int]) -> Optional[CallbackRegistration]:
        """
        Check if a single API call is a callback registration

        Args:
            api_name: API name
            addr: Call address
            tainted_args: List of tainted parameter indices

        Returns:
            CallbackRegistration if callback registration, else None
        """
        if api_name not in self.CALLBACK_APIS:
            return None

        info = self.CALLBACK_APIS[api_name]
        callback_arg = info.get('callback_arg')

        if callback_arg is None:
            return None

        is_callback_tainted = callback_arg in tainted_args

        userdata_arg = info.get('userdata_arg')
        is_userdata_tainted = userdata_arg in tainted_args if userdata_arg else False

        if is_callback_tainted:
            risk_level = info.get('risk_if_tainted', 'High')
            risk_reason = f"Callback function pointer (parameter {callback_arg}) is tainted"
        elif is_userdata_tainted:
            risk_level = "Medium"
            risk_reason = f"User-data (parameter {userdata_arg}) is tainted"
        else:
            risk_level = "Low"
            risk_reason = "Parameters not tainted"

        return CallbackRegistration(
            addr=addr,
            callback_type=info['type'],
            api_name=api_name.decode(),
            callback_arg_index=callback_arg,
            callback_addr=None,
            is_callback_tainted=is_callback_tainted,
            is_userdata_tainted=is_userdata_tainted,
            risk_level=risk_level,
            risk_reason=risk_reason
        )

    def get_dangerous_registrations(self) -> List[CallbackRegistration]:
        """Get dangerous callback registrations"""
        return [r for r in self.registrations
                if r.is_callback_tainted or r.risk_level in ('Critical', 'High')]
