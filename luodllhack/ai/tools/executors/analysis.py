# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/executors/analysis.py
Analysis Tool Executors - Disassembly, Taint analysis
"""

import re
from typing import Dict, Any

from ...compat import (
    parse_address, safe_parse_address,
    HAVE_CAPSTONE, HAVE_VULN_ANALYSIS, HAVE_CORE_UTILS
)

from .base import (
    Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32,
    DANGEROUS_SINKS, TAINT_SOURCES, parse_exports_dict
)


class AnalysisExecutors:
    """
    Analysis Tool Executor Mixin

    Provides:
    - disassemble_function: Disassembly
    - analyze_taint_flow: Taint analysis
    - analyze_cross_function: Cross-function analysis
    - check_dangerous_imports: Dangerous import check
    - find_path_to_sink: Call chain analysis
    """

    def disassemble_function(self, address: str, max_instructions: int = 50) -> Dict:
        """Disassemble function - enhanced version, supports imported function detection"""
        if not HAVE_CAPSTONE or not self.taint_engine:
            return {"error": "Capstone or TaintEngine not available"}

        addr, err = safe_parse_address(address)
        if err:
            return {"error": err}

        try:
            max_instructions = int(max_instructions) if max_instructions else 50
        except (ValueError, TypeError):
            max_instructions = 50

        mode = CS_MODE_64 if self.taint_engine.arch == "x64" else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        # Check if it's an imported function (IAT address)
        if addr in self.taint_engine.import_map:
            api_name = self.taint_engine.import_map[addr]
            api_str = api_name.decode() if isinstance(api_name, bytes) else api_name

            callers = []
            for func_addr, node in self.taint_engine.callgraph.items():
                if addr in node.callees:
                    callers.append(f"0x{func_addr:x}")

            return {
                "is_import": True,
                "import_api": api_str,
                "import_address": f"0x{addr:x}",
                "callers": callers[:10],
                "caller_count": len(callers),
                "note": f"This is an imported function {api_str}, cannot disassemble directly. Suggested to analyze the functions that call it.",
                "suggestion": f"Please use disassemble_function to analyze caller: {callers[0] if callers else 'N/A'}"
            }

        try:
            rva = addr - self.taint_engine.image_base
            if rva < 0 or rva > len(self.taint_engine.binary_data):
                nearest_export = None
                min_dist = float('inf')
                if hasattr(self, 'exports') and self.exports:
                    for name, exp_addr in self.exports.items():
                        dist = abs(exp_addr - addr)
                        if dist < min_dist:
                            min_dist = dist
                            nearest_export = (name, exp_addr)

                if nearest_export and min_dist < 0x1000:
                    return {
                        "error": f"Address 0x{addr:x} is not within valid code range",
                        "suggestion": f"You might want to analyze {nearest_export[0]} (0x{nearest_export[1]:x})",
                        "nearest_export": nearest_export[0],
                        "nearest_address": f"0x{nearest_export[1]:x}"
                    }
                return {"error": f"Invalid address: 0x{addr:x} (RVA: 0x{rva:x} out of range)"}

            offset = self.taint_engine.pe.get_offset_from_rva(rva)

            try:
                offset = int(offset) if offset is not None else -1
            except (TypeError, ValueError):
                return {"error": f"Cannot convert offset to int for RVA 0x{rva:x}"}

            if offset < 0 or offset >= len(self.taint_engine.binary_data):
                return {"error": f"Invalid file offset {offset} for RVA 0x{rva:x}"}

            end_offset = min(offset + max_instructions * 15, len(self.taint_engine.binary_data))
            code = self.taint_engine.binary_data[offset:end_offset]

            instructions = []
            for i, insn in enumerate(md.disasm(code, addr)):
                if i >= max_instructions:
                    break
                instructions.append({
                    "address": f"0x{insn.address:x}",
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex()
                })
                if insn.mnemonic in ['ret', 'retn']:
                    break

            return {
                "function_address": address,
                "instruction_count": len(instructions),
                "instructions": instructions
            }
        except Exception as e:
            return {"error": str(e)}

    def analyze_taint_flow(self, func_address: str, func_name: str) -> Dict:
        """Analyze taint flow"""
        if not self.taint_engine:
            return {"error": "TaintEngine not available"}

        addr, err = safe_parse_address(func_address)
        if err:
            return {"error": err}

        try:
            paths = self.taint_engine.analyze_function(addr, func_name)
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

        result = {
            "function": func_name,
            "address": func_address,
            "taint_paths_found": len(paths),
            "paths": []
        }

        for path in paths:
            result["paths"].append({
                "source": {
                    "type": path.source.type.name,
                    "location": path.source.tainted_location
                },
                "sink": {
                    "api": path.sink.api_name,
                    "vuln_type": path.sink.vuln_type.name,
                    "severity": path.sink.severity,
                    "address": f"0x{path.sink.addr:x}"
                },
                "confidence": path.confidence,
                "step_count": len(path.steps)
            })

        return result

    def analyze_cross_function(self, exports: Dict[str, Any]) -> Dict:
        """Cross-function analysis"""
        if not self.taint_engine:
            return {"error": "TaintEngine not available"}

        if parse_exports_dict is not None:
            export_addrs = parse_exports_dict(exports)
        else:
            export_addrs = {k: parse_address(v) for k, v in exports.items()
                           if v is not None}

        if not export_addrs:
            return {"error": "No valid export addresses"}

        try:
            paths = self.taint_engine.analyze_cross_function(export_addrs)
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

        result = {
            "exports_analyzed": len(export_addrs),
            "cross_function_vulns": len(paths),
            "vulnerabilities": []
        }

        for path in paths:
            result["vulnerabilities"].append({
                "entry_function": path.entry_func,
                "call_chain": path.call_chain,
                "sink": {
                    "api": path.sink.api_name,
                    "vuln_type": path.sink.vuln_type.name,
                    "severity": path.sink.severity
                },
                "confidence": path.confidence
            })

        return result

    def check_dangerous_imports(self) -> Dict:
        """Check for dangerous imports"""
        if not self.taint_engine:
            return {"error": "TaintEngine not available"}

        dangerous = []
        for addr, name in self.taint_engine.import_map.items():
            name_str = name.decode() if isinstance(name, bytes) else name

            if name in DANGEROUS_SINKS:
                info = DANGEROUS_SINKS[name]
                dangerous.append({
                    "api": name_str,
                    "address": f"0x{addr:x}",
                    "vuln_type": info['vuln'].name,
                    "severity": info['severity'],
                    "cwe": info.get('cwe', 'N/A')
                })
            elif name in TAINT_SOURCES:
                info = TAINT_SOURCES[name]
                dangerous.append({
                    "api": name_str,
                    "address": f"0x{addr:x}",
                    "type": "taint_source",
                    "source_type": info['type'].name
                })

        return {
            "total_imports": len(self.taint_engine.import_map),
            "dangerous_count": len(dangerous),
            "dangerous_apis": dangerous
        }

    def find_path_to_sink(self, export_name: str, sink_name: str) -> Dict:
        """Find call path from export function to dangerous sink"""
        if not self.taint_engine:
            return {"error": "TaintEngine not available"}

        exports = self.exports
        if not exports:
            if self.taint_engine.callgraph:
                exports = {
                    node.name: addr
                    for addr, node in self.taint_engine.callgraph.items()
                    if node.is_export
                }

        if not exports:
            return {"error": "No exports available. Please run analyze_cross_function first or provide exports."}

        has_callees = any(
            node.callees for node in self.taint_engine.callgraph.values()
        ) if self.taint_engine.callgraph else False

        if not self.taint_engine.callgraph or not has_callees:
            self.taint_engine.build_callgraph(exports, max_depth=20)

        sink_addr = None
        sink_name_bytes = sink_name.encode() if isinstance(sink_name, str) else sink_name
        for addr, name in self.taint_engine.import_map.items():
            if isinstance(name, bytes):
                if name == sink_name_bytes or name.decode('utf-8', errors='ignore') == sink_name:
                    sink_addr = addr
                    break
            else:
                if name == sink_name:
                    sink_addr = addr
                    break

        if not sink_addr:
            for addr, name in self.taint_engine.import_map.items():
                name_str = name.decode('utf-8', errors='ignore') if isinstance(name, bytes) else name
                if sink_name.lower() in name_str.lower():
                    sink_addr = addr
                    sink_name = name_str
                    break

        if not sink_addr:
            return {"error": f"Sink '{sink_name}' not found in imports"}

        export_addr = None
        for addr, node in self.taint_engine.callgraph.items():
            if node.name == export_name:
                export_addr = addr
                break

        if not export_addr:
            export_addr = exports.get(export_name)
            if export_addr:
                if export_addr not in self.taint_engine.callgraph:
                    return {"error": f"Export '{export_name}' not in callgraph, rebuild may be needed"}

        if not export_addr:
            return {"error": f"Export '{export_name}' not found"}

        export_node = self.taint_engine.callgraph.get(export_addr)
        export_callees_count = len(export_node.callees) if export_node else 0

        path = self.taint_engine._bfs_find_path(export_addr, sink_addr)
        total_nodes = len(self.taint_engine.callgraph)

        if path:
            chain = []
            for addr in path:
                node = self.taint_engine.callgraph.get(addr)
                if node:
                    chain.append(node.name)
            chain.append(sink_name)

            return {
                "path_found": True,
                "export": export_name,
                "sink": sink_name,
                "call_chain": chain,
                "depth": len(chain),
                "graph_nodes": total_nodes
            }
        else:
            return {
                "path_found": False,
                "export": export_name,
                "sink": sink_name,
                "export_addr": f"0x{export_addr:x}",
                "sink_addr": f"0x{sink_addr:x}",
                "export_direct_callees": export_callees_count,
                "note": f"No path found in callgraph containing {total_nodes} nodes.",
                "hint": "Possible reasons: 1) Function does not directly/indirectly call this API 2) Call depth exceeds limit 3) Used dynamic calls",
                "graph_nodes": total_nodes
            }

    def infer_signature(self, func_name: str) -> Dict:
        """Enhanced parameter inference (x64 Windows)"""
        if not self.taint_engine or not self.exports:
            return None

        try:
            addr = self.exports.get(func_name)
            if not addr:
                return None

            reg_args = {
                'rcx': 0, 'ecx': 0, 'cl': 0,
                'rdx': 1, 'edx': 1, 'dl': 1,
                'r8': 2, 'r8d': 2, 'r8w': 2, 'r8b': 2,
                'r9': 3, 'r9d': 3, 'r9w': 3, 'r9b': 3
            }

            args_info = {}
            written_regs = set()
            stack_args_count = 0

            count = 0
            for insn in self.taint_engine.disasm_function(addr):
                if count > 100:
                    break
                count += 1

                mnemonic = insn.mnemonic.lower()
                op_str = insn.op_str.lower()
                ops = [x.strip() for x in op_str.split(',')] if op_str else []

                reads = []
                writes = []

                if mnemonic in ['cmp', 'test', 'and', 'or', 'xor']:
                    reads.extend(ops)
                elif mnemonic in ['mov', 'movzx', 'movsx', 'lea']:
                    if len(ops) >= 2:
                        writes.append(ops[0])
                        reads.append(ops[1])
                elif mnemonic == 'push':
                    reads.extend(ops)
                elif mnemonic == 'pop':
                    writes.extend(ops)

                for op in reads:
                    for reg_name, arg_idx in reg_args.items():
                        if reg_name in op and reg_name not in written_regs:
                            if arg_idx not in args_info:
                                args_info[arg_idx] = {
                                    'type': 'unknown',
                                    'used_at': insn.address,
                                    'is_pointer': False,
                                    'register': reg_name
                                }
                            if '[' in op and reg_name in op:
                                args_info[arg_idx]['is_pointer'] = True
                                args_info[arg_idx]['type'] = 'pointer'

                for op in writes:
                    for reg_name in reg_args.keys():
                        if reg_name == op or op.startswith(reg_name):
                            written_regs.add(reg_name)

                stack_match = re.search(r'\[rsp\s*\+\s*(0x[0-9a-f]+|[0-9]+)\]', op_str)
                if stack_match:
                    offset_str = stack_match.group(1)
                    offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                    if offset >= 0x28:
                        stack_arg_idx = 4 + (offset - 0x28) // 8
                        if stack_arg_idx not in args_info:
                            args_info[stack_arg_idx] = {
                                'type': 'stack',
                                'used_at': insn.address,
                                'is_pointer': False,
                                'stack_offset': offset
                            }
                        stack_args_count = max(stack_args_count, stack_arg_idx - 3)

                if mnemonic == 'call':
                    target = None
                    if insn.operands and insn.operands[0].type == 2:
                        target = insn.operands[0].imm
                    if target:
                        api_name = self.taint_engine.import_map.get(target, b'')
                        if api_name:
                            api_lower = api_name.lower() if isinstance(api_name, str) else api_name.decode().lower()
                            if any(s in api_lower for s in ['str', 'wcs', 'mem', 'sprintf', 'printf']):
                                if 0 in args_info:
                                    args_info[0]['type'] = 'string_ptr'
                                    args_info[0]['is_pointer'] = True

                if mnemonic in ['ret', 'retn']:
                    break

            if not args_info:
                return {"arg_count": 1}

            max_arg_idx = max(args_info.keys())
            arg_count = max_arg_idx + 1

            arg_types = []
            for i in range(arg_count):
                if i in args_info:
                    info = args_info[i]
                    if info['is_pointer']:
                        arg_types.append('ptr')
                    elif info['type'] == 'string_ptr':
                        arg_types.append('str')
                    else:
                        arg_types.append('int')
                else:
                    arg_types.append('int')

            return {
                "arg_count": arg_count,
                "arg_types": arg_types,
                "has_pointer_args": any(info.get('is_pointer') for info in args_info.values()),
                "stack_args": stack_args_count,
                "details": {idx: info for idx, info in args_info.items()}
            }

        except Exception as e:
            print(f"[-] Signature inference failed: {e}")
            return None
