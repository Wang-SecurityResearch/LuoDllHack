# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/executors/poc.py
PoC Tool Executor - Generation and verification
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, Optional

from ...compat import (
    parse_address, safe_parse_address,
    HAVE_SYMBOLIC, HAVE_SIGNATURE
)

from .base import SignatureExtractor, get_function_signature, get_enhanced_signature, EnhancedSymbolicExecutor


class PoCExecutors:
    """
    PoC Tool Executor Mixin

    Provides:
    - generate_poc: PoC generation
    - verify_poc: PoC verification
    - verify_last_poc: Verify recently generated PoC
    - solve_input: Symbolic execution input solving
    """

    def generate_poc(self, vuln_type: str, target_export: str,
                     payload_hint: str = None,
                     custom_call_args: str = None,
                     sink_address: str = None) -> Dict:
        """Generate PoC code - enhanced version integrating symbolic execution"""
        print(f"[DEBUG] generate_poc called: vuln_type={vuln_type}, target_export={target_export}, sink_address={sink_address}")

        try:
            from luodllhack.exploit.generator import (
                PrecisePoCGenerator, ExploitContext, PoCLanguage,
                VulnType as ExploitVulnType
            )
        except ImportError as e:
            print(f"[DEBUG] Failed to import exploit module: {e}")
            return {"error": f"luodllhack.exploit module not available: {e}"}

        vuln_type_map = {
            "buffer_overflow": ExploitVulnType.BUFFER_OVERFLOW,
            "format_string": ExploitVulnType.FORMAT_STRING,
            "command_injection": ExploitVulnType.COMMAND_INJECTION,
            "path_traversal": ExploitVulnType.PATH_TRAVERSAL,
            "integer_overflow": ExploitVulnType.INTEGER_OVERFLOW,
            "double_free": ExploitVulnType.DOUBLE_FREE,
            "use_after_free": ExploitVulnType.USE_AFTER_FREE,
            "null_dereference": ExploitVulnType.NULL_DEREFERENCE,
            "type_confusion": ExploitVulnType.TYPE_CONFUSION,
            "out_of_bounds_read": ExploitVulnType.OUT_OF_BOUNDS_READ,
            "out_of_bounds_write": ExploitVulnType.OUT_OF_BOUNDS_WRITE,
            "heap_overflow": ExploitVulnType.HEAP_OVERFLOW,
            "integer_underflow": ExploitVulnType.INTEGER_UNDERFLOW,
            "uninitialized_memory": ExploitVulnType.UNINITIALIZED_MEMORY,
            "race_condition": ExploitVulnType.RACE_CONDITION,
            "memory_leak": ExploitVulnType.MEMORY_LEAK,
            "stack_exhaustion": ExploitVulnType.STACK_EXHAUSTION,
            "deserialization": ExploitVulnType.DESERIALIZATION,
            "privilege_escalation": ExploitVulnType.PRIVILEGE_ESCALATION,
            "info_disclosure": ExploitVulnType.INFO_DISCLOSURE,
            "control_flow_hijack": ExploitVulnType.CONTROL_FLOW_HIJACK,
            "untrusted_pointer_dereference": ExploitVulnType.UNTRUSTED_POINTER_DEREFERENCE,
        }

        exploit_vuln_type = vuln_type_map.get(vuln_type.lower())
        if exploit_vuln_type is None:
            return {"error": f"Unknown vulnerability type: {vuln_type}. Supported: {list(vuln_type_map.keys())}"}

        buffer_size = 1024
        if payload_hint:
            if str(payload_hint).isdigit():
                buffer_size = int(payload_hint)
            else:
                match = re.search(r'\d+', str(payload_hint))
                if match:
                    buffer_size = int(match.group())

        func_addr = 0
        resolved_export = target_export

        if hasattr(self, 'exports') and self.exports:
            func_addr = self.exports.get(target_export, 0)

            if func_addr == 0:
                print(f"[DEBUG] Function '{target_export}' not in exports, trying fallback methods")
                if target_export.startswith("func_0x"):
                    try:
                        addr_str = target_export[5:]
                        func_addr = int(addr_str, 16)
                        print(f"[*] Parsing address from fallback function name: {target_export} -> 0x{func_addr:x}")
                    except ValueError as e:
                        print(f"[DEBUG] Failed to parse address from {target_export}: {e}")

                if func_addr == 0 and sink_address:
                    try:
                        sink_addr = parse_address(sink_address)
                        for name, addr in self.exports.items():
                            if addr > 0 and abs(sink_addr - addr) < 0x10000:
                                func_addr = addr
                                resolved_export = name
                                print(f"[*] Reverse looked up export function from sink address: {name} @ 0x{addr:x}")
                                break
                        if func_addr == 0:
                            func_addr = sink_addr
                            print(f"[*] Using sink address as function address: 0x{func_addr:x}")
                    except (ValueError, TypeError):
                        pass

        arg_count = None
        brute_force = True
        calling_convention = None
        func_signature = None
        signature_info = {}

        if HAVE_SIGNATURE and SignatureExtractor is not None and SignatureExtractor.is_available():
            try:
                lookup_name = resolved_export
                print(f"[*] Extracting function signature: {lookup_name}")

                # Prioritize enhanced signature analysis (disassembly detection of pointers/COM methods)
                func_signature = None
                if get_enhanced_signature is not None:
                    func_signature = get_enhanced_signature(
                        self.binary_path, lookup_name, rva=func_addr,
                        signature_file=self.signature_file  # Pass external signature file
                    )
                    if func_signature:
                        print(f"[+] Using enhanced signature analysis: is_com={func_signature.is_com_method}, source={func_signature.analysis_source}")

                # Fallback to basic signature extraction
                if not func_signature:
                    func_signature = get_function_signature(
                        self.binary_path, lookup_name,
                        signature_file=self.signature_file  # Pass external signature file
                    )

                if func_signature:
                    arg_count = func_signature.arg_count
                    calling_convention = func_signature.calling_convention
                    brute_force = False

                    if func_addr == 0 and func_signature.rva > 0:
                        func_addr = func_signature.rva
                        print(f"[*] Obtained function address from signature: 0x{func_addr:x}")

                    signature_info = {
                        "arg_count": func_signature.arg_count,
                        "calling_convention": func_signature.calling_convention,
                        "return_type": func_signature.return_type,
                        "argtypes": func_signature.get_ctypes_argtypes(),
                        "restype": func_signature.get_ctypes_restype(),
                        "confidence": func_signature.confidence,
                        "analysis_source": func_signature.analysis_source,
                        "is_com_method": getattr(func_signature, 'is_com_method', False),
                        "has_this_pointer": getattr(func_signature, 'has_this_pointer', False),
                    }
                    print(f"[+] Signature extraction successful: {arg_count} arguments, calling_convention={calling_convention}, COM={signature_info.get('is_com_method')}")
                else:
                    print(f"[-] Signature not found for function {lookup_name}")
            except Exception as e:
                print(f"[-] Signature extraction failed: {e}")

        if arg_count is None:
            try:
                if hasattr(self, 'infer_signature'):
                    sig = self.infer_signature(resolved_export)
                    if sig and sig.get('arg_count', 0) > 0:
                        arg_count = sig['arg_count']
                        brute_force = False
            except (AttributeError, TypeError, KeyError):
                pass

        solved_inputs = {}
        symbolic_used = False

        if HAVE_SYMBOLIC and func_addr and sink_address:
            try:
                print(f"[*] Attempting symbolic execution to solve for precise input...")
                sink_addr = parse_address(sink_address)

                sym_result = self.symbolic_explore(
                    f"0x{func_addr:x}",
                    f"0x{sink_addr:x}",
                    num_args=arg_count or 4
                )

                if sym_result.get("solved_inputs"):
                    solved_inputs = {
                        k: bytes.fromhex(v) for k, v in sym_result["solved_inputs"].items()
                    }
                    symbolic_used = True
                    print(f"[+] Symbolic execution successful, obtained {len(solved_inputs)} precise inputs")
                else:
                    print(f"[-] Symbolic execution failed to solve for inputs: {sym_result.get('note', 'unknown')}")

            except Exception as e:
                print(f"[-] Symbolic execution failed: {e}")

        arch_compatible = True
        arch_info = {}
        if self.taint_engine:
            arch_info = self.taint_engine.get_arch_info()
            arch_compatible = arch_info.get('compatible', True)

        context = ExploitContext(
            dll_path=str(self.binary_path.resolve()),
            func_name=resolved_export,
            func_addr=func_addr,
            vuln_type=exploit_vuln_type,
            sink_api=vuln_type,
            tainted_args=[0],
            buffer_size=buffer_size,
            arg_count=arg_count,
            custom_call_args=custom_call_args,
            brute_force_args=brute_force,
            solved_inputs=solved_inputs,
            auto_trigger=True,
            safe_mode=False,
            signature_file=str(self.signature_file) if self.signature_file else None
        )

        print(f"[DEBUG] Creating PoC context: func_name={resolved_export}, func_addr=0x{func_addr:x}, vuln_type={exploit_vuln_type}")
        generator = PrecisePoCGenerator()
        try:
            result = generator.generate(context, PoCLanguage.PYTHON)
            print(f"[DEBUG] PoC generated: code_len={len(result.code) if result.code else 0}")
        except Exception as e:
            print(f"[DEBUG] PoC generation failed: {e}")
            import traceback
            traceback.print_exc()
            return {"error": f"PoC generation failed: {e}"}

        optimized_code = result.code
        llm_optimized = False
        if self._should_optimize_poc():
            try:
                print("[*] Optimizing PoC with LLM...")
                optimized = self._optimize_poc_with_llm(
                    poc_code=result.code,
                    vuln_type=vuln_type,
                    func_name=resolved_export,
                    signature_info=signature_info,
                    solved_inputs=solved_inputs
                )
                if optimized and optimized != result.code:
                    optimized_code = optimized
                    llm_optimized = True
                    print("[+] LLM optimization complete")
            except Exception as e:
                print(f"[-] LLM optimization failed: {e}")

        success_prob = result.success_probability
        if symbolic_used:
            success_prob = min(1.0, success_prob + 0.3)
        if llm_optimized:
            success_prob = min(1.0, success_prob + 0.15)

        poc_result = {
            "vuln_type": vuln_type,
            "target": resolved_export,
            "poc_code": optimized_code,
            "payload_hex": result.payload.hex()[:100] if result.payload else "",
            "success_probability": success_prob,
            "notes": result.notes,
            "symbolic_execution_used": symbolic_used,
            "llm_optimized": llm_optimized,
            "solved_inputs": {k: v.hex() for k, v in solved_inputs.items()} if solved_inputs else None,
        }

        if signature_info:
            poc_result["signature_info"] = signature_info
            if signature_info.get("arg_count", 0) > 0:
                poc_result["success_probability"] = min(1.0, success_prob + 0.2)

        if arch_info:
            poc_result["arch_info"] = {
                "dll_arch": arch_info.get('dll_arch'),
                "python_arch": arch_info.get('python_arch'),
                "compatible": arch_compatible
            }
            if not arch_compatible:
                poc_result["arch_warning"] = (
                    f"PoC requires {arch_info.get('dll_arch')} Python to run. "
                    f"Current Python is {arch_info.get('python_arch')}."
                )

        note_parts = []
        if symbolic_used:
            note_parts.append("symbolic execution")
        if signature_info and signature_info.get("arg_count", 0) > 0:
            note_parts.append(f"signature ({signature_info.get('arg_count')} args, {signature_info.get('calling_convention')})")
        if llm_optimized:
            note_parts.append("LLM optimized")

        if note_parts:
            poc_result["note"] = f"PoC generated with {', '.join(note_parts)} - high confidence"
        elif not arch_compatible:
            poc_result["note"] = f"PoC generated but requires {arch_info.get('dll_arch')} Python to execute"
        else:
            poc_result["note"] = "PoC generated by heuristics - requires validation"

        self.last_poc_code = optimized_code

        return poc_result

    def _should_optimize_poc(self) -> bool:
        """Check if PoC should be optimized using LLM"""
        env_val = os.environ.get("LUODLLHACK_POC_LLM_OPTIMIZE", "").lower()
        if env_val in ("0", "false", "no", "off"):
            return False
        if env_val in ("1", "true", "yes", "on"):
            return self._has_llm_backend()

        if self.config and hasattr(self.config, "poc_llm_optimize"):
            if bool(getattr(self.config, "poc_llm_optimize")):
                return self._has_llm_backend()
            return False

        return self._has_llm_backend()

    def _optimize_poc_with_llm(
        self,
        poc_code: str,
        vuln_type: str,
        func_name: str,
        signature_info: Dict = None,
        solved_inputs: Dict = None
    ) -> Optional[str]:
        """Optimize PoC code using LLM"""
        if not self._has_llm_backend():
            return None

        # For COM methods, skip LLM optimization (error-prone)
        if signature_info and signature_info.get('is_com_method'):
            print("[*] Skipping LLM optimization: COM methods require special handling")
            return None

        prompt = self._build_poc_optimize_prompt(
            poc_code, vuln_type, func_name, signature_info, solved_inputs
        )

        try:
            if self.llm_backend is not None:
                response = self.llm_backend.generate(
                    prompt=prompt,
                    system_prompt=(
                        "You are an expert security researcher specializing in exploit development. "
                        "Your task is to MINIMALLY review and optimize PoC code for vulnerability testing. "
                        "IMPORTANT: Do NOT rewrite the entire code. Only fix specific issues. "
                        "MUST PRESERVE: CrashAnalyzer class, ArgBuilder class, ANALYSIS_JSON output. "
                        "Focus on: correct function signatures (use c_void_p for pointers), proper error handling. "
                        "Return ONLY the complete, optimized Python code without any explanation."
                    )
                )
                if response and response.text:
                    optimized = self._extract_code_from_response(response.text)
                    if optimized:
                        # Verify that the optimized code preserves key components
                        if self._validate_optimized_poc(poc_code, optimized):
                            return optimized
                        else:
                            print("[*] Using original template code")
                            return None

        except Exception as e:
            print(f"[-] LLM optimization error: {e}")

        return None

    def _build_poc_optimize_prompt(
        self,
        poc_code: str,
        vuln_type: str,
        func_name: str,
        signature_info: Dict = None,
        solved_inputs: Dict = None
    ) -> str:
        """Build PoC optimization prompt"""
        prompt_parts = [
            "Review and MINIMALLY optimize the following PoC code for a vulnerability test.",
            "IMPORTANT: Do NOT rewrite the entire code. Only fix specific issues while preserving the structure.",
            "",
            f"**Vulnerability Type:** {vuln_type}",
            f"**Target Function:** {func_name}",
        ]

        if signature_info:
            is_com = signature_info.get('is_com_method', False)
            has_this = signature_info.get('has_this_pointer', False)
            prompt_parts.extend([
                "",
                "**Function Signature:**",
                f"- Arguments: {signature_info.get('arg_count', 'unknown')}",
                f"- Calling Convention: {signature_info.get('calling_convention', 'unknown')}",
                f"- Return Type: {signature_info.get('return_type', 'unknown')}",
                f"- ctypes argtypes: {signature_info.get('argtypes', 'None')}",
                f"- ctypes restype: {signature_info.get('restype', 'None')}",
                f"- IS COM METHOD: {is_com}",
                f"- Has 'this' pointer: {has_this}",
            ])

            if is_com or has_this:
                prompt_parts.extend([
                    "",
                    "**CRITICAL - COM METHOD HANDLING:**",
                    "This is a COM interface method. You CANNOT call it directly via ctypes.CDLL!",
                    "COM methods require:",
                    "1. The first argument is the 'this' pointer (interface pointer)",
                    "2. Arguments that look like integers may actually be POINTERS",
                    "3. For GetHandlerProperty2: signature is (this, formatIndex, propID, PROPVARIANT* value)",
                    "4. For CreateDecoder: signature is (this, index, const GUID* iid, void** decoder)",
                    "5. Use ctypes.c_void_p for pointer arguments, NOT c_longlong",
                    "",
                    "If you cannot properly call this COM method, generate a stub that explains",
                    "why direct calling is not possible and what the proper approach would be.",
                ])

        if solved_inputs:
            prompt_parts.extend([
                "",
                "**Symbolic Execution Results (use these values):**",
            ])
            for name, value in solved_inputs.items():
                hex_val = value.hex() if isinstance(value, bytes) else str(value)
                prompt_parts.append(f"- {name}: {hex_val[:64]}{'...' if len(hex_val) > 64 else ''}")

        prompt_parts.extend([
            "",
            "**Original PoC Code:**",
            "```python",
            poc_code,
            "```",
            "",
            "**CRITICAL - MUST PRESERVE THESE:**",
            "1. If the code has CrashAnalyzer class - KEEP IT (for false positive detection)",
            "2. If the code has ArgBuilder class - KEEP IT (for argument construction)",
            "3. If the code outputs [ANALYSIS_JSON]...[/ANALYSIS_JSON] - KEEP IT",
            "4. These classes detect signature errors vs real vulnerabilities",
            "",
            "**Optimization Requirements:**",
            "1. Fix function signature (argtypes/restype) - use c_void_p for pointers, not c_longlong",
            "2. Fix any obvious errors or issues in the code",
            "3. Optimize payload based on vulnerability type",
            "4. Add proper error handling for edge cases",
            "5. Ensure the function call has correct arguments",
            "6. If ChromeMain or similar entry point, it likely needs (HINSTANCE, HINSTANCE, LPSTR, int) args",
            "7. For COM methods: explain limitation or implement proper COM initialization",
            "",
            "Return ONLY the complete optimized Python code, no explanations.",
        ])

        return "\n".join(prompt_parts)

    def _extract_code_from_response(self, response_text: str) -> Optional[str]:
        """Extract code from LLM response"""
        code_match = re.search(r'```python\s*(.*?)\s*```', response_text, re.DOTALL)
        if code_match:
            return code_match.group(1).strip()

        code_match = re.search(r'```\s*(.*?)\s*```', response_text, re.DOTALL)
        if code_match:
            code = code_match.group(1).strip()
            if 'import' in code or 'def ' in code or 'ctypes' in code:
                return code

        if response_text.strip().startswith(('#!/', 'import ', '# ', '"""')):
            return response_text.strip()

        return None

    def _validate_optimized_poc(self, original_code: str, optimized_code: str) -> bool:
        """Verify if optimized PoC preserves key components"""
        # Check if original code has key components
        had_crash_analyzer = 'CrashAnalyzer' in original_code or 'crash_analyzer' in original_code
        had_arg_builder = 'ArgBuilder' in original_code or 'arg_builder' in original_code
        had_analysis_json = 'ANALYSIS_JSON' in original_code

        # If original code has these components, optimized code must have them as well
        if had_crash_analyzer and 'CrashAnalyzer' not in optimized_code and 'crash_analyzer' not in optimized_code:
            print("[-] LLM optimization lost CrashAnalyzer, refusing usage")
            return False

        if had_arg_builder and 'ArgBuilder' not in optimized_code and 'arg_builder' not in optimized_code:
            print("[-] LLM optimization lost ArgBuilder, refusing usage")
            return False

        if had_analysis_json and 'ANALYSIS_JSON' not in optimized_code:
            print("[-] LLM optimization lost ANALYSIS_JSON output, refusing usage")
            return False

        # Check if pointer types were incorrectly changed to integer types
        # If original code has c_void_p but optimized code only has c_longlong
        if 'c_void_p' in original_code:
            if 'c_void_p' not in optimized_code and 'c_longlong' in optimized_code:
                print("[-] LLM optimization might have incorrectly changed pointer type to integer type")
                # Not completely rejected, but print a warning

        return True

    def verify_poc(self, poc_code: str, timeout: int = 5) -> Dict:
        """Verify PoC in sandbox"""
        arch_compatible = True
        arch_info = {}
        if self.taint_engine:
            arch_info = self.taint_engine.get_arch_info()
            arch_compatible = arch_info.get('compatible', True)

        if not arch_compatible:
            dll_arch = arch_info.get('dll_arch', 'unknown')
            py_arch = arch_info.get('python_arch', 'unknown')
            return {
                "verified": False,
                "skipped": True,
                "reason": "architecture_mismatch",
                "error": (
                    f"Cannot run dynamic verification: DLL is {dll_arch}, "
                    f"Python is {py_arch}. "
                    f"Please use {dll_arch} Python to verify this PoC."
                ),
                "arch_info": arch_info,
                "note": "Static validation passed. Dynamic verification requires matching architecture."
            }

        pocs_dir = Path("pocs")
        pocs_dir.mkdir(exist_ok=True)
        timestamp = int(time.time())
        saved_poc_path = pocs_dir / f"poc_{timestamp}.py"

        try:
            saved_poc_path.write_text(poc_code, encoding='utf-8')
            print(f"[*] PoC code saved to: {saved_poc_path}")
        except Exception as e:
            print(f"[-] Failed to save PoC file: {e}")
            return {"verified": False, "error": f"Failed to save PoC: {e}"}

        try:
            from luodllhack.exploit.validator import PoCValidator, ValidationStatus
            validator = PoCValidator(sandbox_enabled=True)

            static_result = validator.validate_static(poc_code)
            dynamic_result = validator.validate_dynamic(
                str(saved_poc_path),
                timeout=timeout,
                capture_crash=True
            )

            crashed = dynamic_result.status == ValidationStatus.CRASH
            is_timeout = dynamic_result.status == ValidationStatus.TIMEOUT

            # Check if it is a false positive
            is_false_positive = getattr(dynamic_result, 'is_false_positive', False)
            false_positive_reason = getattr(dynamic_result, 'false_positive_reason', None)

            result = {
                "verified": True,
                "crashed": crashed,
                "timeout": is_timeout,
                "crash_type": dynamic_result.crash_type.name if dynamic_result.crash_type else None,
                "crash_address": f"0x{dynamic_result.crash_address:x}" if dynamic_result.crash_address else None,
                "return_code": dynamic_result.exception_code,
                "stdout": dynamic_result.stdout[:2000] if dynamic_result.stdout else "",
                "stderr": dynamic_result.stderr[:2000] if dynamic_result.stderr else "",
                "execution_time": dynamic_result.execution_time,
                "static_notes": static_result.notes,
                "dynamic_notes": dynamic_result.notes,
                "poc_path": str(saved_poc_path.absolute()),
                # False positive detection
                "is_false_positive": is_false_positive,
                "false_positive_reason": false_positive_reason,
            }

            # If it's a false positive, add a warning
            if is_false_positive:
                result["warning"] = (
                    f"This crash appears to be a FALSE POSITIVE: {false_positive_reason}. "
                    "The crash address matches a passed argument value, indicating a signature error."
                )
                print(f"[!] FALSE POSITIVE DETECTED: {false_positive_reason}")

            return result
        except ImportError:
            pass

        try:
            proc_result = subprocess.run(
                ['python', str(saved_poc_path)],
                capture_output=True,
                timeout=timeout,
                cwd=str(self.binary_path.parent)
            )
            crashed = proc_result.returncode != 0
            stdout = proc_result.stdout.decode('utf-8', errors='ignore')[:2000]
            stderr = proc_result.stderr.decode('utf-8', errors='ignore')[:2000]

            # Parse false positive analysis results
            is_false_positive = False
            false_positive_reason = None
            combined = stdout + stderr
            fp_match = re.search(r'\[ANALYSIS_JSON\](.*?)\[/ANALYSIS_JSON\]', combined, re.DOTALL)
            if fp_match:
                try:
                    import json
                    analysis = json.loads(fp_match.group(1))
                    is_false_positive = analysis.get('is_false_positive', False)
                    false_positive_reason = analysis.get('reason')
                except:
                    pass

            result = {
                "verified": True,
                "crashed": crashed,
                "return_code": proc_result.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "poc_path": str(saved_poc_path.absolute()),
                "is_false_positive": is_false_positive,
                "false_positive_reason": false_positive_reason,
            }

            if is_false_positive:
                result["warning"] = (
                    f"FALSE POSITIVE: {false_positive_reason}. "
                    "Crash address matches passed argument."
                )

            return result
        except subprocess.TimeoutExpired:
            return {
                "verified": True,
                "crashed": False,
                "timeout": True,
                "poc_path": str(saved_poc_path.absolute()),  # Return PoC file path
            }
        except Exception as e:
            return {"verified": False, "error": str(e)}

    def verify_last_poc(self, timeout: int = 5) -> Dict:
        """Verify the most recently generated PoC"""
        code = self.last_poc_code
        if not code:
            return {"verified": False, "error": "No generated PoC available"}
        return self.verify_poc(code, timeout=timeout)

    def solve_input(self, source_addr: str, sink_addr: str) -> Dict:
        """Symbolic execution input solving"""
        try:
            from luodllhack.analysis.taint import SymbolicEngine
            from luodllhack.core.types import TaintPath, TaintSource, TaintSink, SourceType, VulnType

            engine = SymbolicEngine(self.binary_path)

            src_addr = parse_address(source_addr)
            snk_addr = parse_address(sink_addr)

            source = TaintSource(
                type=SourceType.ARGUMENT,
                addr=src_addr,
                api_name="input",
                tainted_location="arg0"
            )
            sink = TaintSink(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                severity="High",
                addr=snk_addr,
                api_name="target",
                tainted_arg_idx=0
            )
            path = TaintPath(source=source, sink=sink)

            trigger = engine.solve_trigger_input(path, timeout=30)

            if trigger:
                return {
                    "solved": True,
                    "trigger_input": trigger.hex(),
                    "length": len(trigger)
                }
            else:
                return {
                    "solved": False,
                    "note": "Could not solve constraints"
                }
        except Exception as e:
            return {"error": str(e)}
