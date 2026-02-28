# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/executors/enhanced.py
Enhanced Analysis Tool Executors - Bounds checking, Lifecycle analysis, Symbolic execution
"""

from typing import Dict, List, Optional

from ...compat import (
    parse_address, safe_parse_address,
    HAVE_CAPSTONE, HAVE_BOUNDS_CHECKER, HAVE_LIFECYCLE, HAVE_SYMBOLIC
)

from .base import (
    Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32,
    DANGEROUS_SINKS, BoundsChecker, LifecycleAnalyzer, LifecycleEvent,
    EnhancedSymbolicExecutor
)

# Vulnerability verifier registry
from .vuln_verifiers import VulnVerifierRegistry


class EnhancedExecutors:
    """
    Enhanced Analysis Tool Executor Mixin

    Provides:
    - check_bounds_before_sink: Bounds check detection
    - analyze_pointer_lifecycle: Pointer lifecycle analysis
    - symbolic_explore: Symbolic execution exploration
    - deep_verify_vulnerability: Comprehensive vulnerability verification
    - verify_all_dangerous_imports: Batch verification of dangerous imports
    """

    def check_bounds_before_sink(self, sink_address: str, tainted_register: str) -> Dict:
        """Detect if there is a bounds check before the sink"""
        if not HAVE_BOUNDS_CHECKER:
            return {"error": "BoundsChecker module not available (luodllhack.analysis.enhanced.bounds_checker)"}

        if not self.taint_engine:
            return {"error": "TaintEngine not initialized"}

        try:
            addr = parse_address(sink_address)

            checker = BoundsChecker(
                binary_data=self.taint_engine.binary_data,
                image_base=self.taint_engine.image_base,
                arch=self.taint_engine.arch,
                pe=self.taint_engine.pe
            )

            result = checker.check_before_sink(
                sink_addr=addr,
                tainted_reg=tainted_register.lower(),
                window=50
            )

            return {
                "sink_address": sink_address,
                "tainted_register": tainted_register,
                "has_bounds_check": result.has_check,
                "check_type": result.check_type.name if result.check_type else None,
                "check_address": f"0x{result.check_addr:x}" if result.check_addr else None,
                "check_instruction": result.check_instruction,
                "is_effective": result.is_effective,
                "effectiveness_reason": result.effectiveness_reason,
                "compared_value": result.compared_value,
                "details": result.details,
                "recommendation": "Potential false positive, effective bounds check exists" if result.is_effective else "Bounds check ineffective or missing, vulnerability likely exploitable"
            }

        except Exception as e:
            return {"error": f"Bounds check analysis failed: {str(e)}"}

    def analyze_pointer_lifecycle(self, func_address: str, func_name: str) -> Dict:
        """Analyze pointer lifecycle, detect UAF/Double-Free"""
        if not HAVE_LIFECYCLE:
            return {"error": "LifecycleAnalyzer module not available (luodllhack.memory.lifecycle)"}

        if not self.taint_engine:
            return {"error": "TaintEngine not initialized"}

        try:
            addr = parse_address(func_address)

            analyzer = LifecycleAnalyzer()

            mode = CS_MODE_64 if self.taint_engine.arch == "x64" else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            rva = addr - self.taint_engine.image_base
            offset = self.taint_engine.pe.get_offset_from_rva(rva)

            try:
                offset = int(offset) if offset is not None else -1
            except (TypeError, ValueError):
                return {"error": f"Cannot convert offset to int for address 0x{addr:x}"}

            if offset < 0 or offset >= len(self.taint_engine.binary_data):
                return {"error": f"Invalid file offset for address 0x{addr:x}"}

            end_offset = min(offset + 2000, len(self.taint_engine.binary_data))
            code = self.taint_engine.binary_data[offset:end_offset]

            alloc_id = 0
            ptr_regs = {}
            findings = []

            from luodllhack.analysis.taint import ALLOC_APIS, FREE_APIS

            for insn in md.disasm(code, addr):
                if insn.mnemonic == 'call':
                    target = None
                    if insn.operands and insn.operands[0].type == 2:
                        target = insn.operands[0].imm

                    if target:
                        api_name = self.taint_engine.import_map.get(target, b'')

                        if api_name in ALLOC_APIS:
                            alloc_id += 1
                            lifecycle = analyzer.track_alloc(
                                alloc_id=alloc_id,
                                addr=insn.address,
                                api=api_name.decode() if isinstance(api_name, bytes) else api_name
                            )
                            ptr_regs['rax'] = alloc_id

                        elif api_name in FREE_APIS:
                            free_info = FREE_APIS[api_name]
                            ptr_arg = free_info.get('ptr_arg', 0)

                            arg_regs = ['rcx', 'rdx', 'r8', 'r9']
                            if ptr_arg < len(arg_regs):
                                freed_reg = arg_regs[ptr_arg]
                                freed_id = ptr_regs.get(freed_reg)

                                if freed_id:
                                    analyzer.track_event(
                                        freed_id,
                                        LifecycleEvent.FREE,
                                        insn.address,
                                        freed_reg
                                    )

                elif insn.mnemonic == 'mov':
                    ops = insn.op_str.split(',')
                    if len(ops) == 2:
                        dest = ops[0].strip().lower()
                        src = ops[1].strip().lower()

                        if src in ptr_regs:
                            ptr_regs[dest] = ptr_regs[src]
                            analyzer.track_event(
                                ptr_regs[src],
                                LifecycleEvent.COPY,
                                insn.address,
                                f"{src} -> {dest}"
                            )

                if insn.mnemonic in ['ret', 'retn']:
                    break

            anomalies = analyzer.detect_anomalies()

            lifecycles_info = []
            for lc_id, lc in analyzer.lifecycles.items():
                lifecycles_info.append({
                    "alloc_id": lc.alloc_id,
                    "alloc_addr": f"0x{lc.alloc_addr:x}",
                    "alloc_api": lc.alloc_api,
                    "is_freed": lc.is_freed,
                    "free_addr": f"0x{lc.free_addr:x}" if lc.free_addr else None,
                    "has_uaf": lc.has_uaf,
                    "has_double_free": lc.has_double_free,
                    "event_count": len(lc.events)
                })

            anomalies_info = []
            for a in anomalies:
                anomalies_info.append({
                    "type": a.anomaly_type,
                    "severity": a.severity,
                    "address": f"0x{a.address:x}",
                    "description": a.description
                })

                if a.anomaly_type in ['DOUBLE_FREE', 'USE_AFTER_FREE']:
                    findings.append({
                        "vuln_type": a.anomaly_type,
                        "severity": a.severity,
                        "address": f"0x{a.address:x}",
                        "func_name": func_name
                    })

            return {
                "func_name": func_name,
                "func_address": func_address,
                "allocations_tracked": len(analyzer.lifecycles),
                "anomalies_found": len(anomalies),
                "lifecycles": lifecycles_info,
                "anomalies": anomalies_info,
                "vulnerabilities": findings
            }

        except Exception as e:
            import traceback
            return {"error": f"Lifecycle analysis failed: {str(e)}", "trace": traceback.format_exc()}

    def symbolic_explore(self, func_address: str, target_sink_address: str,
                         num_args: int = 4) -> Dict:
        """Symbolic execution exploration, collect path constraints and solve for precise input"""
        if not HAVE_SYMBOLIC:
            return {"error": "EnhancedSymbolicExecutor not available (luodllhack.symbolic.executor). Install angr: pip install angr"}

        try:
            func_addr, err = safe_parse_address(func_address)
            if err:
                return {"error": err}
            sink_addr, err = safe_parse_address(target_sink_address)
            if err:
                return {"error": err}

            try:
                num_args = int(num_args) if num_args is not None else 4
            except (ValueError, TypeError):
                num_args = 4

            executor = EnhancedSymbolicExecutor(
                str(self.binary_path),
                auto_load_libs=False
            )

            path_states = executor.explore_with_constraints(
                func_addr=func_addr,
                target_addr=sink_addr,
                max_steps=2000,
                timeout=60
            )

            if not path_states:
                return {
                    "func_address": func_address,
                    "target_sink": target_sink_address,
                    "paths_found": 0,
                    "note": "No paths found to target sink"
                }

            paths_info = []
            solved_inputs = {}

            for i, ps in enumerate(path_states[:5]):
                path_info = {
                    "path_id": ps.path_id,
                    "constraint_count": ps.get_constraint_count(),
                    "reached_target": ps.reached_target,
                    "is_satisfiable": ps.is_satisfiable
                }

                if ps.is_satisfiable and ps.reached_target:
                    try:
                        for var_name, sym_var in ps.symbolic_vars.items():
                            if ps.final_state.solver.satisfiable():
                                concrete = ps.final_state.solver.eval(sym_var.bitvec, cast_to=bytes)
                                solved_inputs[var_name] = concrete.hex()
                                path_info["solved"] = True
                    except (AttributeError, KeyError, ValueError, TypeError):
                        path_info["solved"] = False

                paths_info.append(path_info)

            return {
                "func_address": func_address,
                "target_sink": target_sink_address,
                "paths_found": len(path_states),
                "paths_to_target": sum(1 for p in path_states if p.reached_target),
                "paths_info": paths_info,
                "solved_inputs": solved_inputs,
                "note": "Use solved_inputs for precise PoC generation" if solved_inputs else "No concrete inputs found"
            }

        except Exception as e:
            import traceback
            return {"error": f"Symbolic exploration failed: {str(e)}", "trace": traceback.format_exc()}

    def deep_verify_vulnerability(self, sink_address: str, vuln_type: str,
                                  tainted_arg_index: int = 0) -> Dict:
        """Comprehensive vulnerability verification - fusion of multiple techniques to reduce false positives"""
        try:
            addr, err = safe_parse_address(sink_address)
            if err:
                return {"error": err}

            try:
                tainted_arg_index = int(tainted_arg_index) if tainted_arg_index is not None else 0
            except (ValueError, TypeError):
                tainted_arg_index = 0

            confidence_score = 0.0
            evidence = []
            # recommendations = [] # existing

            arg_regs = ['rcx', 'rdx', 'r8', 'r9']
            tainted_reg = arg_regs[tainted_arg_index] if 0 <= tainted_arg_index < 4 else 'stack'

            # 1. Bounds check analysis (weight: 30%)
            bounds_result = None
            if HAVE_BOUNDS_CHECKER and self.taint_engine:
                try:
                    bounds_result = self.check_bounds_before_sink(sink_address, tainted_reg)

                    if bounds_result.get("error"):
                        evidence.append(f"Bounds check analysis failed: {bounds_result['error']}")
                    elif bounds_result.get("is_effective"):
                        confidence_score -= 0.30
                        evidence.append(f"✗ Found effective bounds check @ {bounds_result.get('check_address')}")
                        recommendations.append("Bounds check exists, likely a false positive")
                    elif bounds_result.get("has_bounds_check"):
                        confidence_score -= 0.15
                        evidence.append(f"△ Found bounds check but might be ineffective @ {bounds_result.get('check_address')}")
                    else:
                        confidence_score += 0.25
                        evidence.append("✓ No bounds check found, vulnerability likely exploitable")
                except Exception as e:
                    evidence.append(f"Bounds check analysis exception: {str(e)}")
            else:
                evidence.append("Bounds check module not available")

            # 2. Vulnerability type specific verification (using strategy pattern registry)
            try:
                verifier_result = VulnVerifierRegistry.verify_all(
                    executor=self,
                    addr=addr,
                    vuln_type=vuln_type,
                    tainted_reg=tainted_reg
                )
                confidence_score += verifier_result.score_delta
                evidence.extend(verifier_result.evidence)
                recommendations.extend(verifier_result.recommendations)
            except Exception as e:
                evidence.append(f"Vulnerability type verification exception: {str(e)}")

            # 3. Taint analysis confirmation (weight: 25%)
            if self.taint_engine:
                taint_confirmed = False
                for path in self.taint_engine.taint_paths:
                    if path.sink and path.sink.addr == addr:
                        taint_confirmed = True
                        confidence_score += 0.25
                        evidence.append(f"✓ Taint analysis confirmed: {path.source.api_name} → {path.sink.api_name}")
                        break

                if not taint_confirmed:
                    evidence.append("△ Taint analysis did not confirm this path")

            # 4. Dangerous API / Vulnerability type confirmation (weight: 20%)
            if self.taint_engine:
                # For CONTROL_FLOW_HIJACK, address is indirect call point, not in import_map
                if vuln_type in ['control_flow_hijack', 'indirect_call']:
                    # Control flow hijack itself is a high-risk vulnerability type
                    confidence_score += 0.15
                    evidence.append(f"✓ Confirmed vulnerability type: Control Flow Hijack (CWE-114)")
                else:
                    api_name = self.taint_engine.import_map.get(addr, b'')

                    if api_name in DANGEROUS_SINKS:
                        sink_info = DANGEROUS_SINKS[api_name]
                        confidence_score += 0.20
                        evidence.append(f"✓ Confirmed dangerous API: {api_name.decode() if isinstance(api_name, bytes) else api_name} ({sink_info.get('cwe', 'N/A')})")
                    else:
                        evidence.append("△ Not in dangerous API list")

            # Final Score
            confidence_score = max(0.0, min(1.0, confidence_score + 0.3))

            if confidence_score >= 0.85:
                level = "Confirmed"
            elif confidence_score >= 0.70:
                level = "High"
            elif confidence_score >= 0.50:
                level = "Medium"
            elif confidence_score >= 0.30:
                level = "Low"
            else:
                level = "Likely False Positive"

            return {
                "sink_address": sink_address,
                "vuln_type": vuln_type,
                "confidence_score": round(confidence_score, 2),
                "confidence_level": level,
                "evidence": evidence,
                "recommendations": recommendations,
                "bounds_check_result": bounds_result,
                "is_likely_exploitable": confidence_score >= 0.50
            }

        except Exception as e:
            import traceback
            return {"error": f"Deep verification failed: {str(e)}", "trace": traceback.format_exc()}

    def verify_all_dangerous_imports(self, max_apis: int = 10) -> Dict:
        """Batch verify all call sites of dangerous imported APIs"""
        if not self.taint_engine:
            return {"error": "TaintEngine not initialized"}

        try:
            max_apis = int(max_apis) if max_apis is not None else 10
        except (ValueError, TypeError):
            max_apis = 10

        dangerous_imports = []
        for iat_addr, name in self.taint_engine.import_map.items():
            if name in DANGEROUS_SINKS:
                info = DANGEROUS_SINKS[name]
                name_str = name.decode() if isinstance(name, bytes) else name

                call_sites = self._find_call_sites_for_import(iat_addr)

                dangerous_imports.append({
                    "iat_address": iat_addr,
                    "call_sites": call_sites,
                    "name": name_str,
                    "vuln_type": info['vuln'].name.lower(),
                    "severity": info['severity'],
                    "cwe": info.get('cwe', 'N/A')
                })

        if not dangerous_imports:
            return {
                "total_dangerous": 0,
                "verified": 0,
                "results": [],
                "note": "No dangerous imports found in this binary"
            }

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        dangerous_imports.sort(key=lambda x: severity_order.get(x['severity'], 4))

        results = []
        verified_count = 0
        total_call_sites = 0

        for imp in dangerous_imports[:max_apis]:
            call_sites = imp['call_sites']
            total_call_sites += len(call_sites)

            if not call_sites:
                results.append({
                    "api": imp['name'],
                    "iat_address": f"0x{imp['iat_address']:x}",
                    "call_sites_found": 0,
                    "status": "unused",
                    "note": "API imported but no call sites found - may be unused"
                })
                continue

            for call_addr in call_sites[:3]:
                try:
                    verify_result = self.deep_verify_vulnerability(
                        sink_address=f"0x{call_addr:x}",
                        vuln_type=imp['vuln_type'],
                        tainted_arg_index=0
                    )

                    if verify_result.get("error"):
                        results.append({
                            "api": imp['name'],
                            "call_site": f"0x{call_addr:x}",
                            "iat_address": f"0x{imp['iat_address']:x}",
                            "status": "error",
                            "error": verify_result['error']
                        })
                    else:
                        verified_count += 1
                        results.append({
                            "api": imp['name'],
                            "call_site": f"0x{call_addr:x}",
                            "iat_address": f"0x{imp['iat_address']:x}",
                            "vuln_type": imp['vuln_type'],
                            "cwe": imp['cwe'],
                            "confidence_score": verify_result.get('confidence_score', 0),
                            "confidence_level": verify_result.get('confidence_level', 'Unknown'),
                            "is_likely_exploitable": verify_result.get('is_likely_exploitable', False),
                            "evidence_summary": verify_result.get('evidence', [])[:3]
                        })

                except Exception as e:
                    results.append({
                        "api": imp['name'],
                        "call_site": f"0x{call_addr:x}",
                        "status": "exception",
                        "error": str(e)
                    })

        results.sort(key=lambda x: x.get('confidence_score', 0), reverse=True)

        high_confidence = [r for r in results if r.get('confidence_score', 0) >= 0.7]
        likely_exploitable = [r for r in results if r.get('is_likely_exploitable', False)]

        return {
            "total_dangerous_apis": len(dangerous_imports),
            "total_call_sites": total_call_sites,
            "verified": verified_count,
            "high_confidence_count": len(high_confidence),
            "likely_exploitable_count": len(likely_exploitable),
            "results": results,
            "recommendation": (
                f"Found {len(likely_exploitable)} likely exploitable call sites, prioritize analysis"
                if likely_exploitable
                else "No high-confidence vulnerabilities found, manual audit of key functions recommended"
            )
        }

    def _find_call_sites_for_import(self, iat_addr: int) -> List[int]:
        """Find all code locations calling a specific IAT address"""
        call_sites = []

        if hasattr(self.taint_engine, 'callgraph'):
            for func_addr, node in self.taint_engine.callgraph.items():
                if hasattr(node, 'callees') and iat_addr in node.callees:
                    call_sites.append(func_addr)

        if not call_sites and HAVE_CAPSTONE:
            try:
                call_sites = self._scan_for_call_instructions(iat_addr)
            except (ValueError, AttributeError, KeyError):
                pass

        return call_sites

    def _scan_for_call_instructions(self, target_addr: int, max_scan: int = 100000) -> List[int]:
        """Scan code segment to find CALL instructions to the specified address"""
        if not self.taint_engine:
            return []

        mode = CS_MODE_64 if self.taint_engine.arch == "x64" else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        call_sites = []

        try:
            for section in self.taint_engine.pe.sections:
                if b'.text' in section.Name:
                    code_start = section.VirtualAddress + self.taint_engine.image_base
                    code_data = section.get_data()[:max_scan]

                    for inst in md.disasm(code_data, code_start):
                        if inst.mnemonic == 'call':
                            op_str = inst.op_str
                            if f'0x{target_addr:x}' in op_str.lower():
                                call_sites.append(inst.address)
                            elif inst.operands:
                                for op in inst.operands:
                                    if hasattr(op, 'mem') and op.mem.disp == target_addr:
                                        call_sites.append(inst.address)
                    break
        except Exception:
            pass

        return call_sites[:20]

    def _check_call_target_validation(self, func_addr: int, call_addr: int) -> bool:
        """
        Check if there is target address validation logic before an indirect call

        Common validation patterns:
        1. Compare with known function table address (cmp + jne/je)
        2. Range check (cmp + ja/jb)
        3. CFI check (test + jz)

        Returns:
            True if validation logic found, False otherwise
        """
        if not HAVE_CAPSTONE or not self.taint_engine:
            return False

        try:
            mode = CS_MODE_64 if self.taint_engine.arch == "x64" else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            # Get function code
            rva = func_addr - self.taint_engine.image_base
            offset = self.taint_engine.pe.get_offset_from_rva(rva)

            if offset is None or offset < 0:
                return False

            # Only analyze window before call (max 100 bytes)
            window_start = max(0, offset)
            call_rva = call_addr - self.taint_engine.image_base
            call_offset = self.taint_engine.pe.get_offset_from_rva(call_rva)

            if call_offset is None:
                return False

            window_size = min(call_offset - offset, 100)
            if window_size <= 0:
                return False

            code_data = self.taint_engine.binary_data[window_start:window_start + window_size]

            # Analyze instructions to finding validation patterns
            cmp_found = False
            test_found = False

            for inst in md.disasm(code_data, func_addr):
                if inst.address >= call_addr:
                    break

                mnemonic = inst.mnemonic.lower()

                # Check comparison instruction
                if mnemonic == 'cmp':
                    cmp_found = True

                # Check test instruction (common for CFI checks)
                if mnemonic == 'test':
                    test_found = True

                # If conditional jump closely follows cmp/test, might be validation logic
                if (cmp_found or test_found) and mnemonic in ['je', 'jne', 'ja', 'jb', 'jae', 'jbe', 'jz', 'jnz']:
                    return True

            return False

        except Exception:
            return False
