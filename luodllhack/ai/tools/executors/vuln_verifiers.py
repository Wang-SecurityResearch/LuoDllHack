# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/executors/vuln_verifiers.py
Vulnerability Type Specific Verifiers - Strategy Pattern

Each vulnerability type can register its own verification logic, instead of hardcoding in deep_verify_vulnerability.
"""

from typing import Dict, List, Callable, Optional, Any, TYPE_CHECKING
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

if TYPE_CHECKING:
    from .enhanced import EnhancedExecutors


@dataclass
class VerificationResult:
    """Verification result"""
    score_delta: float = 0.0  # Confidence score change (-1.0 to 1.0)
    evidence: List[str] = field(default_factory=list)  # Evidence list
    recommendations: List[str] = field(default_factory=list)  # Recommendation list
    extra_data: Dict[str, Any] = field(default_factory=dict)  # Extra data


class VulnVerifier(ABC):
    """Vulnerability verifier base class"""

    # Vulnerability types this verifier applies to
    vuln_types: List[str] = []

    # Verification weight (0.0 - 1.0)
    weight: float = 0.25

    @abstractmethod
    def verify(self, executor: 'EnhancedExecutors', addr: int,
               tainted_reg: str, **kwargs) -> VerificationResult:
        """Execute verification"""
        pass


# =============================================================================
# Concrete Verifier Implementations
# =============================================================================

class MemoryLifecycleVerifier(VulnVerifier):
    """Memory lifecycle verifier - for UAF, Double-Free"""

    vuln_types = ['use_after_free', 'double_free']
    weight = 0.25

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            from ...compat import HAVE_LIFECYCLE
            if not HAVE_LIFECYCLE:
                result.evidence.append("Memory lifecycle module not available")
                return result

            func_addr = executor._find_function_containing(addr)
            if not func_addr:
                result.evidence.append("Unable to locate function containing address")
                return result

            lifecycle_result = executor.analyze_pointer_lifecycle(
                f"0x{func_addr:x}",
                f"func_{func_addr:x}"
            )

            if lifecycle_result.get("anomalies_found", 0) > 0:
                result.score_delta = 0.25
                result.evidence.append(
                    f"✓ Lifecycle analysis found {lifecycle_result['anomalies_found']} anomalies"
                )
            else:
                result.evidence.append("△ Lifecycle analysis found no anomalies")

            result.extra_data['lifecycle_result'] = lifecycle_result

        except Exception as e:
            result.evidence.append(f"Lifecycle analysis exception: {str(e)}")

        return result


class ControlFlowHijackVerifier(VulnVerifier):
    """Control flow hijack verifier"""

    vuln_types = ['control_flow_hijack', 'indirect_call']
    weight = 0.25

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            # Check if indirect call target is tainted
            indirect_call_verified = False
            if executor.taint_engine:
                for path in executor.taint_engine.taint_paths:
                    if path.sink and path.sink.addr == addr:
                        indirect_call_verified = True
                        result.score_delta = 0.25
                        source_api = path.source.api_name if path.source else "unknown"
                        result.evidence.append(
                            f"✓ Control flow hijack verification: indirect call target influenced by {source_api}"
                        )

                        # Check taint propagation chain length
                        if hasattr(path, 'path_length') and path.path_length < 5:
                            result.score_delta += 0.10
                            result.evidence.append(
                                f"✓ Short taint chain (length={path.path_length}), easier to exploit"
                            )
                        break

            if not indirect_call_verified:
                result.evidence.append("△ Indirect call target control not confirmed")

            # Check for CFI protection
            from ...compat import HAVE_CAPSTONE
            if executor.pe and HAVE_CAPSTONE:
                try:
                    func_addr = executor._find_function_containing(addr)
                    if func_addr:
                        has_validation = executor._check_call_target_validation(func_addr, addr)
                        if has_validation:
                            result.score_delta -= 0.15
                            result.evidence.append("△ Found call target validation logic, might be protected")
                        else:
                            result.score_delta += 0.10
                            result.evidence.append("✓ No call target validation found, high exploitability")
                except Exception:
                    pass

        except Exception as e:
            result.evidence.append(f"Control flow hijack analysis exception: {str(e)}")

        return result


class FormatStringVerifier(VulnVerifier):
    """Format string verifier"""

    vuln_types = ['format_string']
    weight = 0.25

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            # Check if format parameter of formatting function is tainted
            if executor.taint_engine:
                for path in executor.taint_engine.taint_paths:
                    if path.sink and path.sink.addr == addr:
                        result.score_delta = 0.20
                        result.evidence.append(
                            f"✓ Format string parameter controlled by user input"
                        )

                        # Format string vulnerabilities are usually dangerous
                        if path.source:
                            source_type = getattr(path.source, 'source_type', None)
                            if source_type and 'NETWORK' in str(source_type):
                                result.score_delta += 0.10
                                result.evidence.append("✓ From network input, high risk")
                        break
                else:
                    result.evidence.append("△ Format parameter control not confirmed")

            # Check formatting API
            api_name = executor.taint_engine.import_map.get(addr, b'') if executor.taint_engine else b''
            dangerous_format_apis = [b'printf', b'sprintf', b'fprintf', b'vsprintf', b'syslog']
            if any(api in api_name for api in dangerous_format_apis):
                result.score_delta += 0.15
                result.evidence.append(f"✓ Confirmed dangerous formatting API: {api_name.decode() if isinstance(api_name, bytes) else api_name}")

        except Exception as e:
            result.evidence.append(f"Format string analysis exception: {str(e)}")

        return result


class IntegerOverflowVerifier(VulnVerifier):
    """Integer overflow verifier"""

    vuln_types = ['integer_overflow', 'integer_underflow']
    weight = 0.20

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            from ...compat import HAVE_CAPSTONE
            if not HAVE_CAPSTONE or not executor.taint_engine:
                result.evidence.append("Integer overflow analysis module not available")
                return result

            # Analyze instructions near address to finding arithmetic operations
            from .base import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

            mode = CS_MODE_64 if executor.taint_engine.arch == "x64" else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)

            # Get function code
            func_addr = executor._find_function_containing(addr)
            if not func_addr:
                result.evidence.append("△ Unable to locate function for integer overflow analysis")
                return result

            rva = func_addr - executor.taint_engine.image_base
            offset = executor.taint_engine.pe.get_offset_from_rva(rva)

            if offset is None or offset < 0:
                return result

            # Analyze first 200 bytes for arithmetic instructions
            code_data = executor.taint_engine.binary_data[offset:offset + 200]
            arithmetic_ops = []
            overflow_check_found = False

            for inst in md.disasm(code_data, func_addr):
                if inst.address > addr:
                    break

                mnemonic = inst.mnemonic.lower()

                # Arithmetic operation instructions
                if mnemonic in ['add', 'sub', 'mul', 'imul', 'shl', 'shr']:
                    arithmetic_ops.append(f"{mnemonic} {inst.op_str}")

                # Overflow check (jo, jno after arithmetic)
                if mnemonic in ['jo', 'jno', 'js', 'jns']:
                    overflow_check_found = True

            if arithmetic_ops:
                result.evidence.append(f"✓ Found arithmetic operations: {', '.join(arithmetic_ops[:3])}")
                result.score_delta += 0.15

            if overflow_check_found:
                result.score_delta -= 0.20
                result.evidence.append("△ Found overflow check, might be protected")
            else:
                result.score_delta += 0.10
                result.evidence.append("✓ No overflow check found")

        except Exception as e:
            result.evidence.append(f"Integer overflow analysis exception: {str(e)}")

        return result


class CommandInjectionVerifier(VulnVerifier):
    """Command injection verifier"""

    vuln_types = ['command_injection']
    weight = 0.25

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            if not executor.taint_engine:
                return result

            # Check command execution API
# ERROR in previous turn, correcting
            api_name = executor.taint_engine.import_map.get(addr, b'')
            dangerous_cmd_apis = [
                b'system', b'WinExec', b'ShellExecute', b'CreateProcess',
                b'popen', b'execl', b'execv', b'_wsystem'
            ]

            if any(api in api_name for api in dangerous_cmd_apis):
                result.score_delta += 0.25
                result.evidence.append(
                    f"✓ Confirmed dangerous command execution API: {api_name.decode() if isinstance(api_name, bytes) else api_name}"
                )

                # Check if command parameters are controlled
                for path in executor.taint_engine.taint_paths:
                    if path.sink and path.sink.addr == addr:
                        result.score_delta += 0.15
                        result.evidence.append("✓ Command parameters controlled by user input")

                        # From network is more dangerous
                        if path.source:
                            source_type = getattr(path.source, 'source_type', None)
                            if source_type and 'NETWORK' in str(source_type):
                                result.score_delta += 0.10
                                result.evidence.append("✓ From network input, Remote Command Execution")
                                result.recommendations.append("Fix immediately! Remote Command Injection vulnerability")
                        break
            else:
                result.evidence.append("△ No matching known command execution API")

        except Exception as e:
            result.evidence.append(f"Command injection analysis exception: {str(e)}")

        return result


class PathTraversalVerifier(VulnVerifier):
    """Path traversal verifier"""

    vuln_types = ['path_traversal']
    weight = 0.20

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            if not executor.taint_engine:
                return result

            # Check file operation API
            api_name = executor.taint_engine.import_map.get(addr, b'')
            file_apis = [
                b'fopen', b'CreateFile', b'DeleteFile', b'MoveFile',
                b'CopyFile', b'LoadLibrary', b'open', b'_wfopen'
            ]

            if any(api in api_name for api in file_apis):
                result.score_delta += 0.15
                result.evidence.append(
                    f"✓ Confirmed file operation API: {api_name.decode() if isinstance(api_name, bytes) else api_name}"
                )

                # LoadLibrary is particularly dangerous
                if b'LoadLibrary' in api_name:
                    result.score_delta += 0.15
                    result.evidence.append("✓ LoadLibrary can lead to code execution")
                    result.recommendations.append("Path traversal + LoadLibrary = code execution")

        except Exception as e:
            result.evidence.append(f"Path traversal analysis exception: {str(e)}")

        return result


class UninitializedMemoryVerifier(VulnVerifier):
    """Uninitialized memory verifier"""

    vuln_types = ['uninitialized_memory']
    weight = 0.20

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            from ...compat import HAVE_CAPSTONE
            if not HAVE_CAPSTONE or not executor.taint_engine:
                result.evidence.append("Uninitialized memory analysis module not available")
                return result

            from .base import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

            mode = CS_MODE_64 if executor.taint_engine.arch == "x64" else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)

            func_addr = executor._find_function_containing(addr)
            if not func_addr:
                result.evidence.append("△ Unable to locate function")
                return result

            rva = func_addr - executor.taint_engine.image_base
            offset = executor.taint_engine.pe.get_offset_from_rva(rva)

            if offset is None or offset < 0:
                return result

            # Analyze function start (max 200 bytes)
            code_data = executor.taint_engine.binary_data[offset:offset + 200]

            has_init = False
            has_early_return = False
            has_param_check = False
            early_cmp_count = 0

            for inst in md.disasm(code_data, func_addr):
                mnemonic = inst.mnemonic.lower()
                op_str = inst.op_str.lower()

                # Check initialization patterns
                if 'xor' in mnemonic and ('eax, eax' in op_str or 'r' in op_str and op_str.split(',')[0] == op_str.split(',')[1].strip()):
                    has_init = True
                if 'rep' in mnemonic and 'stos' in mnemonic:
                    has_init = True

                # Check parameter validation patterns (common at function start)
                # test rcx, rcx; jz error_path
                # cmp rdx, 0; je error_path
                if mnemonic in ['test', 'cmp']:
                    early_cmp_count += 1
                    if any(r in op_str for r in ['rcx', 'rdx', 'r8', 'r9', 'ecx', 'edx']):
                        has_param_check = True

                # Check for early return (error handling)
                if mnemonic == 'ret' and (inst.address - func_addr) < 100:
                    has_early_return = True

                # Check for error return pattern following conditional jump
                if mnemonic in ['je', 'jz', 'jne', 'jnz'] and has_param_check:
                    has_early_return = True

                if inst.address - func_addr > 150:
                    break

            # Evaluate results
            if has_param_check and has_early_return:
                result.score_delta -= 0.25
                result.evidence.append("△ Found parameter validation + early return pattern, likely a false positive")
                result.recommendations.append("Function has input validation, manual confirmation recommended")
            elif has_init:
                result.score_delta -= 0.15
                result.evidence.append("△ Found initialization code, likely a false positive")
            elif early_cmp_count >= 2:
                result.score_delta -= 0.10
                result.evidence.append("△ Function has multiple conditional checks, might be protected")
            else:
                result.score_delta += 0.15
                result.evidence.append("✓ No initialization or validation code found, potential uninitialized memory use")

        except Exception as e:
            result.evidence.append(f"Uninitialized memory analysis exception: {str(e)}")

        return result


class UntrustedPointerVerifier(VulnVerifier):
    """Untrusted pointer dereference verifier"""

    vuln_types = ['untrusted_pointer_dereference', 'untrusted_ptr']
    weight = 0.25

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            # This is a dangerous vulnerability type - reading a pointer from external input and dereferencing it
            result.score_delta = 0.20
            result.evidence.append("✓ Untrusted pointer dereference: value read from parameter pointer is used as a pointer")

            # Check taint path
            if executor.taint_engine:
                for path in executor.taint_engine.taint_paths:
                    if path.sink and path.sink.addr == addr:
                        if path.source:
                            source_type = getattr(path.source, 'source_type', None)
                            if source_type and 'NETWORK' in str(source_type):
                                result.score_delta += 0.15
                                result.evidence.append("✓ From network input, remotely exploitable")
                                result.recommendations.append("High risk! Attacker can control pointer value")
                            elif source_type and 'FILE' in str(source_type):
                                result.score_delta += 0.10
                                result.evidence.append("✓ From file input")
                        break

            result.recommendations.append("Recommendation: Validate pointer value within legal range before dereferencing")

        except Exception as e:
            result.evidence.append(f"Untrusted pointer analysis exception: {str(e)}")

        return result


class BufferOverflowVerifier(VulnVerifier):
    """Buffer overflow verifier"""

    vuln_types = ['buffer_overflow', 'heap_overflow', 'out_of_bounds_read', 'out_of_bounds_write']
    weight = 0.20

    def verify(self, executor, addr, tainted_reg, **kwargs) -> VerificationResult:
        result = VerificationResult()

        try:
            if not executor.taint_engine:
                return result

            # Check for dangerous string/memory operation APIs
            api_name = executor.taint_engine.import_map.get(addr, b'')
            dangerous_apis = [
                b'strcpy', b'strcat', b'sprintf', b'gets', b'memcpy',
                b'memmove', b'wcscpy', b'wcscat', b'lstrcpy', b'lstrcat'
            ]
            safer_apis = [
                b'strncpy', b'strncat', b'snprintf', b'memcpy_s',
                b'strcpy_s', b'strcat_s'
            ]

            if any(api in api_name for api in dangerous_apis):
                result.score_delta += 0.20
                result.evidence.append(
                    f"✓ Use of unsafe API: {api_name.decode() if isinstance(api_name, bytes) else api_name}"
                )

                # Check if 'n' version is available but not used
                base_api = api_name.replace(b'W', b'A').replace(b'A', b'')
                if base_api + b'n' in str(executor.taint_engine.import_map.values()):
                    result.recommendations.append(f"Recommended to use {base_api.decode()}n version")

            elif any(api in api_name for api in safer_apis):
                result.evidence.append(
                    f"△ Use of safer API: {api_name.decode() if isinstance(api_name, bytes) else api_name}"
                )
                # But still need to check if length parameter is correct
                result.score_delta += 0.05

        except Exception as e:
            result.evidence.append(f"Buffer overflow analysis exception: {str(e)}")

        return result


# =============================================================================
# Verifier Registry
# =============================================================================

class VulnVerifierRegistry:
    """Vulnerability verifier registry"""

    _verifiers: List[VulnVerifier] = []

    @classmethod
    def register(cls, verifier: VulnVerifier):
        """Register a verifier"""
        cls._verifiers.append(verifier)

    @classmethod
    def get_verifiers(cls, vuln_type: str) -> List[VulnVerifier]:
        """Get verifiers applicable to the specified vulnerability type"""
        vuln_type_lower = vuln_type.lower()
        return [v for v in cls._verifiers if vuln_type_lower in v.vuln_types]

    @classmethod
    def verify_all(cls, executor: 'EnhancedExecutors', addr: int,
                   vuln_type: str, tainted_reg: str, **kwargs) -> VerificationResult:
        """Execute all applicable verifiers"""
        combined = VerificationResult()

        verifiers = cls.get_verifiers(vuln_type)
        if not verifiers:
            combined.evidence.append(f"△ No specific verifier for vulnerability type {vuln_type}")
            return combined

        for verifier in verifiers:
            try:
                result = verifier.verify(executor, addr, tainted_reg, **kwargs)
                combined.score_delta += result.score_delta * verifier.weight
                combined.evidence.extend(result.evidence)
                combined.recommendations.extend(result.recommendations)
                combined.extra_data.update(result.extra_data)
            except Exception as e:
                combined.evidence.append(f"Verifier {verifier.__class__.__name__} exception: {e}")

        return combined


# =============================================================================
# Automatically register all verifiers
# =============================================================================

def _register_all():
    """Register all built-in verifiers"""
    verifiers = [
        MemoryLifecycleVerifier(),
        ControlFlowHijackVerifier(),
        FormatStringVerifier(),
        IntegerOverflowVerifier(),
        CommandInjectionVerifier(),
        PathTraversalVerifier(),
        UninitializedMemoryVerifier(),
        UntrustedPointerVerifier(),
        BufferOverflowVerifier(),
    ]
    for v in verifiers:
        VulnVerifierRegistry.register(v)


_register_all()
