# -*- coding: utf-8 -*-
"""
luodllhack/ai/security.py
Security analysis and AI-powered vulnerability assessment.
"""

import os
import json
import time
import datetime
from pathlib import Path
from typing import Dict, List, Any

from luodllhack.dll_hijack.constants import (
    MACHINE_I386, MACHINE_AMD64, X86_REG_RIP,
    DLL_CHAR_DYNAMIC_BASE, DLL_CHAR_NX_COMPAT, DLL_CHAR_NO_SEH,
    DLL_CHAR_GUARD_CF, DLL_CHAR_FORCE_INTEGRITY, DLL_CHAR_HIGH_ENTROPY_VA,
    SECTION_MEM_EXECUTE, SECTION_MEM_READ, SECTION_MEM_WRITE,
    YARA_RULES, BANNED_APIS, HEURISTIC_BEHAVIORS, KNOWN_DLLS
)
from luodllhack.dll_hijack.utils import resolve_forwarder_module, WinTrustVerifier, SecurityUtils

# Optional dependencies
try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_OP_IMM, CS_OP_MEM, CS_OP_REG
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

try:
    import angr
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False

try:
    import google.generativeai as genai
    HAVE_GENAI = True
except ImportError:
    HAVE_GENAI = False



class AIAgent:
    """Handles interaction with LLM for Security Analysis (Powered by Gemini SDK)."""
    def __init__(self) -> None:
        if not HAVE_GENAI:
            self.api_key = None
            return
        # Use env var or the provided key
        self.api_key = os.environ.get("GEMINI_API_KEY", "AIzaSyD9jOwHu1Gzr3HaIuX-HUC5BF5gWxn2QZ8")
        if self.api_key:
            genai.configure(api_key=self.api_key)

    def analyze(self, metadata: Dict[str, Any]) -> None:
        if not HAVE_GENAI:
            print("\n    - [AI Analysis] Skipped: google-generativeai library not installed")
            return
        if not self.api_key:
            print("\n    - [AI Analysis] Skipped: GEMINI_API_KEY environment variable not set")
            return

        print("\n    - [AI Analysis] Connecting to Gemini LLM for security risk assessment...")

        prompt = f"""
You are a professional binary security analysis expert. Your task is to analyze the security detection results of this DLL and assess its **risk of malicious exploitation** (e.g., DLL hijacking, code injection, etc.).

Please use Chain of Thought (CoT) for analysis:

## Analysis Data
{json.dumps(metadata, indent=2, ensure_ascii=False)}

## Analysis Requirements

### 1. Security Posture Observation
- Check mitigation status (ASLR/DEP/CFG/GS)
- Identify high-risk sections (Writable and Executable)
- Analyze imported dangerous APIs
- Assess hijacking feasibility score

### 2. Exploitation Risk Reasoning
Please reason step-by-step:
- Missing ASLR → Predictable addresses → Lower exploitation difficulty
- Missing DEP → Executable stack/heap → Shellcode can be executed directly
- High-entropy sections → Possible packing → Hidden malicious code
- Presence of TLS callbacks → Can be used for anti-debugging/early execution
- High hijacking score → Suitable as a DLL hijacking target

### 3. Risk Level Determination
Based on the above reasoning, provide:
- **Hijacking Risk**: [Extreme/High/Medium/Low]
- **Injection Risk**: [Extreme/High/Medium/Low]
- **Overall Security Level**: [Dangerous/Warning/Normal/Safe]

### 4. Security Hardening Recommendations
Provide specific hardening measures for discovered issues.

Please output in English with a clear format.
"""
        
        try:
            model = genai.GenerativeModel('gemini-2.5-flash')
            response = model.generate_content(prompt)

            # Check if response was blocked
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                print(f"      [!] Request blocked: {response.prompt_feedback.block_reason}")
                return

            if response.text:
                print("\n" + "=" * 60)
                print(" AI Security Risk Assessment Report")
                print("=" * 60)
                print(response.text)
            else:
                print("      [!] No valid text generated (possible security filtering)")

        except Exception as e:
            print(f"      [!] AI analysis failed: {str(e)}")

class SecurityAnalyzer:
    """Performs static analysis on PE files using pefile, YARA, and Capstone."""
    def __init__(self, dll_path: Path, follow_thunks: bool = False,
                 angr_load_libs: bool = False, angr_max_exports: int = 8,
                 angr_timeout_ms: int = 5000):
        self.dll_path = dll_path
        self.follow_thunks = follow_thunks
        self.angr_load_libs = angr_load_libs
        self.angr_max_exports = angr_max_exports
        self.angr_timeout_ms = angr_timeout_ms
        self.pe = None
        self.file_data = None
        self.metadata = {
            "filename": dll_path.name,
            "entry_point": "", "image_base": "", "compile_time": "",
            "mitigations": [], "sections": [], "imports_sample": [],
            "risk_factors": [], "suspicious_apis": [], "heuristics": [],
            "yara_matches": [], "entry_point_disasm": [], "hijack_score": 10
        }

    def analyze(self) -> None:
        if not HAVE_PEFILE:
            print("    - [!] pefile library not installed, skipping deep PE analysis (pip install pefile)")
            return

        try:
            self.pe = pefile.PE(str(self.dll_path))
            with open(self.dll_path, 'rb') as f:
                self.file_data = f.read()

            self._basic_info()
            self._check_mitigations()
            self._check_load_config()
            self._check_relocations_aslr()
            self._check_sections()
            self._check_imports()
            self._check_tls_callbacks()
            self._check_heuristics()
            self._check_exports_security()
            self._scan_yara()
            self._disassemble_entry()
            try:
                self._build_import_iat_map()
            except Exception:
                self._import_iat_map = {}
            self._scan_function_vulnerabilities()
            self._infer_export_prototypes()
            self._infer_export_prototypes_angr()
            self._scan_angr_path_vulnerabilities()
            self._assess_hijack_risk()

            # Print Summary
            self._print_summary()

            # AI Analysis - Send analytical results to LLM for summary
            agent = AIAgent()
            agent.analyze(self.metadata)

        except Exception as e:
            print(f"    - [PE Analysis] Analysis failed: {e}")

    def _resolve_export_target(self, exp) -> Dict[str, Any]:
        if not self.follow_thunks:
            return {"module_path": None, "image_base": self.pe.OPTIONAL_HEADER.ImageBase, "rva": exp.address, "reason": "local", "external": False}
        try:
            image_base = self.pe.OPTIONAL_HEADER.ImageBase
            rva = exp.address
            if getattr(exp, 'forwarder', None):
                fwd = exp.forwarder
                if isinstance(fwd, bytes):
                    fwd = fwd.decode('utf-8', errors='ignore')
                if '.' in fwd:
                    mod, rest = fwd.split('.', 1)
                else:
                    mod, rest = fwd, ''
                mod_resolved = resolve_forwarder_module(mod)
                sysroot = Path(os.environ.get('SystemRoot', r'C:\Windows'))
                mod_path = sysroot / 'System32' / f"{mod_resolved}.dll"
                if not mod_path.exists():
                    return {"module_path": None, "image_base": image_base, "rva": rva, "reason": "forwarder_module_missing", "external": True}
                pe2 = pefile.PE(str(mod_path))
                if not hasattr(pe2, 'DIRECTORY_ENTRY_EXPORT'):
                    return {"module_path": str(mod_path), "image_base": pe2.OPTIONAL_HEADER.ImageBase, "rva": None, "reason": "no_export_table", "external": True}
                target_name = None
                target_ord = None
                if rest:
                    if rest.startswith('#'):
                        try:
                            target_ord = int(rest[1:])
                        except ValueError:
                            target_ord = None
                    else:
                        target_name = rest
                found = None
                for s in pe2.DIRECTORY_ENTRY_EXPORT.symbols:
                    nm = s.name.decode('utf-8', errors='ignore') if s.name else None
                    if target_name and nm == target_name:
                        found = s
                        break
                    if target_ord is not None and int(getattr(s, 'ordinal', -1)) == target_ord:
                        found = s
                        break
                if found is not None:
                    if getattr(found, 'forwarder', None):
                        return {"module_path": str(mod_path), "image_base": pe2.OPTIONAL_HEADER.ImageBase, "rva": None, "reason": "forwarder_chain", "external": True}
                    return {"module_path": str(mod_path), "image_base": pe2.OPTIONAL_HEADER.ImageBase, "rva": found.address, "reason": "forwarder_resolved", "external": True}
                return {"module_path": str(mod_path), "image_base": pe2.OPTIONAL_HEADER.ImageBase, "rva": None, "reason": "forwarder_symbol_missing", "external": True}
            import struct
            try:
                offset = self.pe.get_offset_from_rva(rva)
                if offset is None or not isinstance(offset, int) or offset < 0:
                    return {"module_path": None, "image_base": image_base, "rva": rva, "reason": "invalid_offset", "external": False}
                code = self.file_data[offset : offset + 12]
                md = Cs(CS_ARCH_X86, CS_MODE_64 if self.pe.FILE_HEADER.Machine == MACHINE_AMD64 else CS_MODE_32)
                md.detail = True
                insns = list(md.disasm(code, image_base + rva))
                if insns:
                    ins = insns[0]
                    if ins.mnemonic == 'jmp' and ins.operands:
                        op = ins.operands[0]
                        if op.type == 1:
                            tgt = op.imm
                            lo = image_base
                            hi = image_base + self.pe.OPTIONAL_HEADER.SizeOfImage
                            if lo <= tgt < hi:
                                return {"module_path": None, "image_base": image_base, "rva": tgt - image_base, "reason": "local_jmp", "external": False}
                        elif op.type == 2:
                            try:
                                base_reg = op.mem.base
                                disp = op.mem.disp
                                if base_reg == X86_REG_RIP:
                                    iat_va = ins.address + ins.size + disp
                                    iat_rva = iat_va - image_base
                                    info = getattr(self, '_import_iat_map', {}).get(iat_rva)
                                    if info and info.get('dll') and info.get('name'):
                                        mod = info['dll']
                                        name = info['name']
                                        mod_resolved = resolve_forwarder_module(mod)
                                        sysroot = Path(os.environ.get('SystemRoot', r'C:\Windows'))
                                        mod_path = sysroot / 'System32' / f"{mod_resolved}.dll"
                                        if mod_path.exists():
                                            pe2 = pefile.PE(str(mod_path))
                                            if hasattr(pe2, 'DIRECTORY_ENTRY_EXPORT'):
                                                for s in pe2.DIRECTORY_ENTRY_EXPORT.symbols:
                                                    nm = s.name.decode('utf-8', errors='ignore') if s.name else None
                                                    if nm == name:
                                                        return {"module_path": str(mod_path), "image_base": pe2.OPTIONAL_HEADER.ImageBase, "rva": s.address, "reason": "iat_forward_resolved", "external": True}
                            except Exception:
                                pass
                            return {"module_path": None, "image_base": image_base, "rva": rva, "reason": "iat_jmp", "external": True}
            except Exception:
                pass
            return {"module_path": None, "image_base": image_base, "rva": rva, "reason": "local_default", "external": False}
        except Exception:
            return {"module_path": None, "image_base": self.pe.OPTIONAL_HEADER.ImageBase, "rva": exp.address, "reason": "error", "external": False}

    def _build_import_iat_map(self) -> None:
        m = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore') if getattr(entry, 'dll', None) else None
                for imp in entry.imports:
                    if imp.name:
                        rva = imp.address - self.pe.OPTIONAL_HEADER.ImageBase
                        m[rva] = {"dll": dll_name, "name": imp.name.decode('utf-8', errors='ignore')}
        self._import_iat_map = m

    def _collect_param_positions(self, pe_obj, file_bytes, image_base, rva) -> List[str]:
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_OP_REG, CS_OP_MEM
        except Exception:
            return []
        is64 = (pe_obj.FILE_HEADER.Machine == MACHINE_AMD64)
        md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
        md.detail = True
        positions = []
        seen_regs = set()
        written_regs = set()
        param_regs = ("rcx","rdx","r8","r9") if is64 else ("ecx","edx")
        stack_bases = ("rsp","rbp") if is64 else ("esp","ebp")
        stack_thresh = 0x20 if is64 else 8
        dest_ops = {"mov","lea","xor","add","sub","and","or","imul"}
        try:
            offset = pe_obj.get_offset_from_rva(rva)
            if offset is None or not isinstance(offset, int) or offset < 0:
                return []
            code = file_bytes[offset : offset + 2048]
        except Exception:
            return []
        for ins in md.disasm(code, image_base + rva):
            if ins.mnemonic == "ret":
                break
            # destination register
            dst_reg_name = None
            if ins.mnemonic in dest_ops and ins.operands:
                dst = ins.operands[0]
                if dst.type == CS_OP_REG:
                    dst_reg_name = ins.reg_name(dst.reg)
                    if dst_reg_name in param_regs:
                        written_regs.add(dst_reg_name)
            # source operand analysis
            if len(ins.operands) >= 2:
                src = ins.operands[1]
                if src.type == CS_OP_REG:
                    src_reg = ins.reg_name(src.reg)
                    if src_reg in param_regs and src_reg not in written_regs and src_reg not in seen_regs:
                        seen_regs.add(src_reg)
                        positions.append(src_reg)
                elif src.type == CS_OP_MEM:
                    base = src.mem.base
                    base_name = ins.reg_name(base) if base != 0 else None
                    disp = src.mem.disp
                    # only count stack arguments on LOADs: mov reg, [mem]
                    if base_name in stack_bases and disp >= stack_thresh and ins.operands[0].type == CS_OP_REG:
                        pos = f"stack+0x{disp:x}"
                        if pos not in positions:
                            positions.append(pos)
        return positions

    def _normalize_signature(self, func_name: str, cc: str, arg_locs: List[str], ret_kind: str) -> str:
        parts = []
        for p in arg_locs:
            t = "int"
            lp = p.lower()
            if lp.startswith("stack+"):
                t = "ptr"
            elif lp in ("rcx","rdx","r8","r9","ecx","edx"):
                t = "int"
            parts.append(f"{p}:{t}")
        return f"{cc} {func_name}({', '.join(parts)}) -> {ret_kind}"

    def _basic_info(self) -> None:
        ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ib = self.pe.OPTIONAL_HEADER.ImageBase
        self.metadata["entry_point"] = hex(ep)
        self.metadata["image_base"] = hex(ib)
        print(f"    - [PE Analysis] Entry Point: 0x{ep:x}")
        print(f"    - [PE Analysis] Image Base: 0x{ib:x}")
        
        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        try:
            ts_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            self.metadata["compile_time"] = ts_str
            print(f"    - [PE Analysis] Compile Time: {ts_str}")
        except (ValueError, OSError, OverflowError):
            self.metadata["compile_time"] = f"Invalid ({timestamp})"
            print(f"    - [PE Analysis] Compile Time: Invalid Timestamp ({timestamp})")

    def _check_mitigations(self) -> None:
        dll_chars = self.pe.OPTIONAL_HEADER.DllCharacteristics
        print("    - [Vulnerability Detection] Binary Exploit Mitigations:")
        
        mitigations = {
            "ASLR (Dynamic Base)": bool(dll_chars & DLL_CHAR_DYNAMIC_BASE),
            "DEP (NX Compat)": bool(dll_chars & DLL_CHAR_NX_COMPAT),
            "NO_SEH (No Structured Exception Handling)": bool(dll_chars & DLL_CHAR_NO_SEH),
            "CFG (Control Flow Guard)": bool(dll_chars & DLL_CHAR_GUARD_CF),
            "Force Integrity": bool(dll_chars & DLL_CHAR_FORCE_INTEGRITY),
            "High Entropy VA": bool(dll_chars & DLL_CHAR_HIGH_ENTROPY_VA)
        }
        
        self.metadata["mitigations"] = mitigations
        
        vulnerable_config = False
        for name, enabled in mitigations.items():
            if enabled:
                print(f"      [+] {name}: Enabled")
            else:
                print(f"      [-] {name}: DISABLED (Vulnerable)")
                vulnerable_config = True
                
        if not mitigations["ASLR (Dynamic Base)"]:
            print("          -> Warning: Missing ASLR, attackers can easily build ROP chains")
        if not mitigations["DEP (NX Compat)"]:
            print("          -> Warning: Missing DEP, shellcode on the stack can be executed directly")

    def _check_sections(self) -> None:
        print("    - [Vulnerability Detection] Section Analysis (Permissions & Entropy):")
        has_rwe = False
        for section in self.pe.sections:
            props = section.Characteristics
            is_exec = bool(props & SECTION_MEM_EXECUTE)
            is_read = bool(props & SECTION_MEM_READ)
            is_write = bool(props & SECTION_MEM_WRITE)
            
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = SecurityUtils.calculate_entropy(section.get_data())
            
            self.metadata["sections"].append({
                "name": name, "r": is_read, "w": is_write, "e": is_exec,
                "entropy": round(entropy, 2)
            })
            
            if is_exec and is_write and is_read:
                print(f"      [!] Warning: RWE (Read-Write-Execute) section found: {name} (Entropy: {entropy:.2f})")
                has_rwe = True
            elif is_write and is_exec:
                print(f"      [!] Warning: WX (Write-Execute) section found: {name} (Entropy: {entropy:.2f})")
                has_rwe = True
            elif entropy > 7.0:
                print(f"      [?] Note: Section {name} has high entropy ({entropy:.2f}), possibly compressed or encrypted")
        
        if not has_rwe:
            print("      [+] No suspicious RWE/WX sections found")

    def _check_imports(self) -> None:
        print("    - [Vulnerability Detection] SDL Violation/Dangerous API Scan:")
        found_banned = []
        has_gs = False
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if not imp.name: continue
                    func_name = imp.name.decode('utf-8')
                    if len(self.metadata["imports_sample"]) < 20:
                        self.metadata["imports_sample"].append(func_name)
                    
                    if imp.name in BANNED_APIS:
                        reason = BANNED_APIS[imp.name]
                        found_banned.append(f"{func_name} ({reason})")
                    if imp.name == b"__security_check_cookie":
                        has_gs = True
        
        self.metadata["suspicious_apis"] = found_banned
        if found_banned:
            print(f"      [!] Found {len(found_banned)} unsafe APIs (SDL Banned):")
            for f in list(set(found_banned)): print(f"        * {f}")
        else:
            print("      [+] No explicitly imported known unsafe APIs found")
            
        if has_gs:
            print("      [+] Stack Protection (GS): Enabled (Mitigates Buffer Overflow)")
        else:
            print("      [-] Stack Protection (GS): DISABLED (Vulnerable to Stack Overflow)")

    def _check_heuristics(self) -> None:
        print("    - [Algorithm Detection] Import Table Heuristic Analysis:")
        detected = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'): return
        
        imported_funcs = set()
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name: imported_funcs.add(imp.name.decode('utf-8', errors='ignore'))
        
        for category, apis in HEURISTIC_BEHAVIORS.items():
            matches = [api for api in apis if any(api.lower() in func.lower() for func in imported_funcs)]
            if matches:
                detected.append(f"{category} (Found {len(matches)} APIs: {', '.join(matches)})")
        
        self.metadata["heuristics"] = detected
        if detected:
            for h in detected: print(f"      [!] {h}")
        else:
            print("      [+] No obvious malicious behavior patterns found")

    def _check_exports_security(self) -> None:
        print("    - [Deep Detection] Export Function Abnormal Pattern Analysis:")
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("      [+] No export table found")
            return

        suspicious_exports = []
        high_entropy_names = []
        abnormal_locations = []
        trampolines = []
        forwarders_info = []
        ordinal_only = []
        
        # Pre-calculate section ranges for fast lookup
        section_ranges = []
        for section in self.pe.sections:
            start = section.VirtualAddress
            end = start + section.Misc_VirtualSize
            props = section.Characteristics
            is_write = bool(props & SECTION_MEM_WRITE)
            is_exec = bool(props & SECTION_MEM_EXECUTE)
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_ranges.append((start, end, name, is_write, is_exec))

        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        
        # Analyze exports
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            rva = exp.address
            if not exp.name:
                ordinal_only.append(f"#{exp.ordinal} -> RVA 0x{rva:x}")
                if getattr(exp, 'forwarder', None):
                    fwd = exp.forwarder
                    if isinstance(fwd, bytes):
                        fwd = fwd.decode('utf-8', errors='ignore')
                    forwarders_info.append(f"#{exp.ordinal} -> {fwd}")
                continue
            func_name = exp.name.decode('utf-8', errors='ignore')
            
            # 1. Name Analysis
            if func_name == "ReflectiveLoader":
                suspicious_exports.append(f"{func_name} (Cobalt Strike feature)")
            
            entropy = SecurityUtils.calculate_entropy(func_name.encode())
            if entropy > 4.5 and len(func_name) > 8:
                high_entropy_names.append(f"{func_name} (Entropy: {entropy:.2f})")

            # 2. Location Analysis (Address in Writable Section?)
            in_valid_section = False
            for start, end, sec_name, is_w, is_x in section_ranges:
                if start <= rva < end:
                    in_valid_section = True
                    if is_w:
                        abnormal_locations.append(f"{func_name} -> {sec_name} (Writable section! Suspected Shellcode/Hook)")
                    break
            
            if not in_valid_section and rva != 0:
                 # Forwarders might have RVA inside export directory or 0, but pefile handles forwarders.
                 # If rva points outside sections, it might be weird unless it's a pure forwarder string pointer.
                 pass

            # 3. Code Analysis (Trampoline/Shim Detection)
            if HAVE_CAPSTONE and in_valid_section:
                try:
                    offset = self.pe.get_offset_from_rva(rva)
                    if offset is None or not isinstance(offset, int) or offset < 0:
                        continue
                    # Read first 16 bytes
                    code = self.file_data[offset : offset + 16]
                    md = Cs(CS_ARCH_X86, CS_MODE_64 if self.pe.FILE_HEADER.Machine == MACHINE_AMD64 else CS_MODE_32)

                    instrs = list(md.disasm(code, image_base + rva))
                    if instrs:
                        first = instrs[0]
                        # Check for JMP (E9, EB, FF 25...)
                        if first.mnemonic.startswith("jmp"):
                            trampolines.append(f"{func_name} -> JMP {first.op_str} (Suspected forwarding/hijacking)")
                except Exception:
                    pass

        # Report findings
        self.metadata["export_analysis"] = {
            "suspicious_names": suspicious_exports,
            "high_entropy_names": high_entropy_names,
            "writable_section_exports": abnormal_locations,
            "trampolines": trampolines,
            "ordinal_only_exports": ordinal_only,
            "forwarders": forwarders_info
        }
        
        if suspicious_exports:
            for s in suspicious_exports: print(f"      [!] High-risk export name found: {s}")
        
        if abnormal_locations:
            for s in abnormal_locations: print(f"      [!!!] CRITICAL WARNING: Export function located in writable section: {s}")
        elif trampolines:
             print(f"      [!] Found {len(trampolines)} direct jump (Trampoline) export functions (Suspected hijacking/proxying)")
             for t in trampolines: print(f"        * {t}")
        
        if high_entropy_names:
            print(f"      [?] Found {len(high_entropy_names)} high-entropy export names (Suspected randomly generated):")
            for n in high_entropy_names: print(f"        * {n}")
        if ordinal_only:
            print(f"      [!] Found {len(ordinal_only)} ordinal-only exports (No public names):")
            for o in ordinal_only: print(f"        * {o}")
        if forwarders_info:
            print(f"      [!] Found {len(forwarders_info)} forwarder exports:")
            for f in forwarders_info: print(f"        * {f}")
            
        if not (suspicious_exports or abnormal_locations or trampolines or high_entropy_names):
            print("      [+] Export function structure and patterns are normal")

    def _check_load_config(self) -> None:
        print("    - [Vulnerability Detection] LoadConfig Security Configuration:")
        lc = getattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG', None)
        if not lc:
            print("      [!] No LoadConfig entry")
            return
        s = lc.struct
        gs_enabled = bool(getattr(s, 'SecurityCookie', 0))
        guard_flags = int(getattr(s, 'GuardFlags', 0))
        seh_table = int(getattr(s, 'SEHandlerTable', 0))
        seh_count = int(getattr(s, 'SEHandlerCount', 0))
        if gs_enabled:
            print("      [+] GS: Enabled")
        else:
            print("      [-] GS: Disabled")
        if guard_flags:
            print("      [+] CFG: GuardFlags present")
        else:
            print("      [~] CFG: No GuardFlags found")
        if self.pe.FILE_HEADER.Machine == MACHINE_I386 and seh_table and seh_count:
            print("      [+] SafeSEH: Enabled")

    def _check_relocations_aslr(self) -> None:
        print("    - [Vulnerability Detection] Relocation Table (ASLR Validity):")
        try:
            idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']
            dirent = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            has_reloc = bool(dirent.Size and dirent.VirtualAddress)
            if has_reloc:
                print("      [+] Relocation table exists")
            else:
                if bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & DLL_CHAR_DYNAMIC_BASE):
                    print("      [!] Dynamic base enabled but relocation table missing -> ASLR may be invalid")
                    self.metadata["risk_factors"].append("ASLR may be invalid (missing relocation table)")
                else:
                    print("      [+] ASLR not enabled, and no relocation table")
        except Exception as e:
            print(f"      [!] Relocation table check failed: {e}")

    def _check_tls_callbacks(self) -> None:
        print("    - [Vulnerability Detection] TLS Callback Analysis:")
        tls = getattr(self.pe, 'DIRECTORY_ENTRY_TLS', None)
        if not tls:
            print("      [+] No TLS callbacks found")
            return
        addr = int(getattr(tls.struct, 'AddressOfCallbacks', 0))
        if addr:
            self.metadata["tls_callbacks"] = [hex(addr)]
            print(f"      [!] TLS callback found: {hex(addr)}")
        else:
            print("      [+] No valid TLS callback address parsed")

    def _scan_yara(self) -> None:
        print("    - [Open Source Library Analysis] YARA Signature Scan:")
        if not HAVE_YARA:
            print("      [!] yara-python not installed, skipping scan")
            return
        
        try:
            rules = yara.compile(source=YARA_RULES)
            matches = rules.match(str(self.dll_path))
            results = [f"{m.rule} ({m.meta.get('description', '')})" for m in matches]
            self.metadata["yara_matches"] = results
            
            if results:
                for r in results: print(f"      [!] {r}")
            else:
                print("      [+] No YARA rule matches found")
        except Exception as e:
            print(f"      [!] YARA scan error: {e}")

    def _disassemble_entry(self) -> None:
        print("    - [Open Source Library Analysis] Entry Point Instruction Disassembly:")
        if not HAVE_CAPSTONE:
            print("      [!] capstone not installed, skipping disassembly")
            return
            
        try:
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = self.pe.OPTIONAL_HEADER.ImageBase
            ep_offset = self.pe.get_offset_from_rva(ep)
            code = self.file_data[ep_offset : ep_offset + 32]
            
            machine = self.pe.FILE_HEADER.Machine
            if machine == MACHINE_AMD64: md = Cs(CS_ARCH_X86, CS_MODE_64)
            elif machine == MACHINE_I386: md = Cs(CS_ARCH_X86, CS_MODE_32)
            else:
                print("      [-] Architecture not supported")
                return

            disasm = []
            for i in md.disasm(code, image_base + ep):
                instr = f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}"
                disasm.append(instr)
            
            self.metadata["entry_point_disasm"] = disasm
            if disasm:
                for instr in disasm: print(f"      * {instr}")
            else:
                print("      [+] Disassembly result is empty")
        except Exception as e:
            print(f"      [!] Disassembly failed: {e}")

    def _scan_function_vulnerabilities(self) -> None:
        """
        Deep Binary Analysis: Disassembles export functions to find:
        1. Stack Buffer Overflows (e.g., lea rax, [rbp-XX] -> call strcpy)
        2. Format String Bugs (e.g., call printf with non-const format)
        3. Integer Overflows (e.g., mul -> malloc)
        """
        print("    - [Deep Vulnerability Mining] Binary Code Audit (Capstone Powered):")
        if not HAVE_CAPSTONE or not self.pe:
            print("      [!] Missing Capstone library, skipping deep code audit")
            return

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return

        # 1. Build Import Map (RVA -> Name) to resolve calls
        import_map = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        # Map Thunk RVA to Name
                        # Note: pefile provides address (VA), we need RVA usually
                        # But calls often point to the IAT entry.
                        # For simplicity, we map the IAT address (imp.address - ImageBase)
                        rva = imp.address - self.pe.OPTIONAL_HEADER.ImageBase
                        import_map[rva] = imp.name.decode('utf-8')
        
        # Also add known unsafe functions if they are internal (symbol check) - omitted for now
        
        vuln_findings = []
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        
        # Configure Capstone
        arch = CS_ARCH_X86
        mode = CS_MODE_64 if self.pe.FILE_HEADER.Machine == MACHINE_AMD64 else CS_MODE_32
        md = Cs(arch, mode)
        md.detail = True # Enable detailed instruction info
        
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name: continue
            func_name = exp.name.decode('utf-8')
            rva = exp.address
            
            # Skip if RVA is 0 or outside file
            try:
                offset = self.pe.get_offset_from_rva(rva)
            except Exception:
                continue
                
            # Read first 300 bytes of function
            code_chunk = self.file_data[offset : offset + 300]
            
            # Disassemble
            instrs = list(md.disasm(code_chunk, image_base + rva))
            
            # Analyze instructions window
            for i, instr in enumerate(instrs):
                # Check for CALL
                if instr.mnemonic.startswith("call"):
                    target_name = None
                    
                    # Resolve Target
                    # Case 1: Indirect Call (call qword ptr [rip + offset]) -> IAT
                    if instr.operands and instr.operands[0].type == CS_OP_MEM:
                        # This requires calculating the memory address (RIP relative for x64)
                        if mode == CS_MODE_64 and instr.operands[0].mem.base == X86_REG_RIP:
                            # Actually easier to use the detailed analysis if needed, but simple heuristic:
                            # Parse op_str like "qword ptr [0x12345]"
                            # But Capstone resolves rip-relative in op_str usually
                            pass
                    
                    # Heuristic: Check if op_str contains a known address from our map
                    # Or check immediate if direct call
                    
                    # SIMPLIFIED: Search import map for any address mentioned in op_str?
                    # Better: Assume we can't easily resolve IAT without complex emulation.
                    # Fallback: Look for standard names in symbol table if debug symbols exist? No.
                    
                    # IMPROVED APPROACH: Use pattern matching for the *arguments* regardless of call target,
                    # OR match against known IAT offsets if possible.
                    
                    # Let's try to find if the call targets a BANNED API by checking if the IAT address is referenced.
                    # For this PoC, we will simulate detection if we find specific register patterns 
                    # before a call, assuming the call *might* be dangerous.
                    
                    # To be robust without full symbol resolution:
                    # We look for:
                    #  1. LEA Reg, [Stack]  (Prepare buffer)
                    #  2. CALL ...          (If we can identify this as strcpy/gets/scanf)
                    
                    # Since we can't perfectly identify 'strcpy' without symbols/IAT resolution,
                    # We will implement the check: "Stack Buffer passed to External Call"
                    # And refine if we can map the import.
                    
                    pass

                # --- VULNERABILITY PATTERNS ---
                
                # 1. Stack Buffer Overflow Heuristic (LEA reg, [rbp-XX] ... CALL)
                # If we see LEA of a stack variable, followed by it being the 1st/2nd arg to a call.
                if instr.mnemonic == "lea":
                    # Check if operand is stack-based (rbp/rsp relative)
                    op = instr.operands[1]
                    if op.type == CS_OP_MEM and (op.mem.base in [29, 30] or op.mem.base in [107, 108]): # X86_REG_RBP/RSP approx
                        # Found stack buffer load.
                        # Look ahead for a CALL instruction within next 5 instructions
                        for j in range(1, 6):
                            if i + j >= len(instrs): break
                            next_ins = instrs[i+j]
                            if next_ins.mnemonic.startswith("call"):
                                # Potential Buffer Overflow Context
                                # If we could resolve the name, we'd be sure. 
                                # For now, we flag "Stack Reference passed to Function"
                                # We can check if the function is in our BANNED list by matching IAT.
                                
                                # Try to resolve call target address
                                target_addr = -1
                                if next_ins.operands[0].type == CS_OP_IMM:
                                    target_addr = next_ins.operands[0].imm
                                elif next_ins.operands[0].type == CS_OP_MEM and next_ins.operands[0].mem.disp != 0:
                                    # RIP relative?
                                    if mode == CS_MODE_64 and next_ins.operands[0].mem.base == X86_REG_RIP:
                                        target_addr = next_ins.address + next_ins.size + next_ins.operands[0].mem.disp
                                
                                # Check if target_addr is in import_map
                                target_rva = target_addr - image_base
                                if target_rva in import_map:
                                    api_name = import_map[target_rva]
                                    if api_name.encode() in BANNED_APIS:
                                        vuln_findings.append(f"{func_name}: Stack Buffer (LEA {instr.op_str}) passed to BANNED API '{api_name}' -> HIGH BOF RISK")
                
                # 2. Format String Bug (CALL printf with non-const RDX/RCX)
                # Hard without CFG. Skip for now.
                
                # 3. Integer Overflow (MUL followed by Allocation)
                if instr.mnemonic in ["mul", "imul"]:
                     # Look ahead for malloc/VirtualAlloc
                     for j in range(1, 10):
                        if i + j >= len(instrs): break
                        next_ins = instrs[i+j]
                        if next_ins.mnemonic.startswith("call"):
                             # Again, resolve target
                             target_addr = -1
                             if next_ins.operands[0].type == CS_OP_MEM and mode == CS_MODE_64:
                                  target_addr = next_ins.address + next_ins.size + next_ins.operands[0].mem.disp
                             
                             target_rva = target_addr - image_base
                             if target_rva in import_map:
                                 api = import_map[target_rva]
                                 if api in ["malloc", "VirtualAlloc", "LocalAlloc", "HeapAlloc"]:
                                     vuln_findings.append(f"{func_name}: Multiplication result used in '{api}' -> Potential Integer Overflow")

        if vuln_findings:
            for v in vuln_findings:
                print(f"      [!!!] {v}")
            self.metadata["binary_vulns"] = vuln_findings
        else:
            print("      [+] No high-confidence binary vulnerability patterns found")

    def _infer_export_prototypes(self) -> None:
        print("    - [Prototype Inference] Export Function Arguments & Returns:")
        results = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("      [+] No export table found")
            return
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        arch = CS_ARCH_X86
        mode = CS_MODE_64 if self.pe.FILE_HEADER.Machine == MACHINE_AMD64 else CS_MODE_32
        use_regs = []
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                continue
            func_name = exp.name.decode('utf-8', errors='ignore')
            target = self._resolve_export_target(exp)
            target_rva = target["rva"]
            target_image_base = target["image_base"]
            pe_obj = self.pe
            file_bytes = self.file_data
            if target["module_path"] and target_rva is not None:
                try:
                    pe2 = pefile.PE(target["module_path"])
                    pe_obj = pe2
                    with open(target["module_path"], 'rb') as f:
                        file_bytes = f.read()
                    image_base = target_image_base
                except Exception:
                    pass
            rva = target_rva if target_rva is not None else exp.address
            try:
                offset = pe_obj.get_offset_from_rva(rva)
                code = file_bytes[offset : offset + 1024]
            except Exception:
                continue
            md = Cs(arch, mode)
            md.detail = True
            regs_used = set()
            stack_offsets = set()
            ret_imm = None
            ret_kind = "unknown"
            last_ret_write = None
            for ins in md.disasm(code, image_base + rva):
                for op in ins.operands:
                    if op.type == CS_OP_REG:
                        reg = op.reg
                        reg_name = ins.reg_name(reg)
                        regs_used.add(reg_name)
                    elif op.type == CS_OP_MEM:
                        base = op.mem.base
                        base_name = ins.reg_name(base) if base != 0 else None
                        disp = op.mem.disp
                        if base_name in ("rsp", "esp", "rbp", "ebp") and disp >= 0:
                            stack_offsets.add(disp)
                if ins.mnemonic == "mov" and ins.operands and len(ins.operands) >= 2:
                    dst = ins.operands[0]
                    src = ins.operands[1]
                    dst_reg = ins.reg_name(dst.reg) if dst.type == 1 else None
                    if dst_reg in ("eax", "rax"):
                        if src.type == 3:
                            try:
                                immv = src.imm
                                if immv in (0,1):
                                    ret_kind = "bool"
                                else:
                                    ret_kind = "int"
                            except (AttributeError, TypeError):
                                ret_kind = "int"
                        elif src.type == 2:
                            ret_kind = "ptr"
                        elif src.type == 1:
                            ret_kind = "int"
                        last_ret_write = ins
                if ins.mnemonic.startswith("set") and ins.operands:
                    dst = ins.operands[0]
                    if dst.type == CS_OP_REG and ins.reg_name(dst.reg) == "al":
                        ret_kind = "bool"
                        last_ret_write = ins
                if ins.mnemonic == "movzx" and len(ins.operands) >= 2:
                    dst = ins.operands[0]
                    src = ins.operands[1]
                    if dst.type == CS_OP_REG and ins.reg_name(dst.reg) in ("eax","rax"):
                        if src.type == CS_OP_REG and ins.reg_name(src.reg) == "al":
                            ret_kind = "bool"
                            last_ret_write = ins
                if ins.mnemonic == "lea" and ins.operands and len(ins.operands) >= 2:
                    dst = ins.operands[0]
                    dst_reg = ins.reg_name(dst.reg) if dst.type == 1 else None
                    if dst_reg in ("eax", "rax"):
                        ret_kind = "ptr"
                        last_ret_write = ins
                if ins.mnemonic == "xor" and ins.operands and len(ins.operands) >= 2:
                    dst = ins.operands[0]
                    src = ins.operands[1]
                    if dst.type == 1 and src.type == 1:
                        if ins.reg_name(dst.reg) in ("eax","rax") and ins.reg_name(src.reg) in ("eax","rax"):
                            ret_kind = "bool"
                            last_ret_write = ins
                if ins.mnemonic == "ret" and ins.op_str:
                    try:
                        ret_imm = int(ins.op_str, 0)
                    except ValueError:
                        ret_imm = None
            # normalized param positions
            param_positions = self._collect_param_positions(pe_obj, file_bytes, image_base, rva)
            if mode == CS_MODE_64:
                arg_count = len(param_positions)
                cc = "win64"
                proto_est = f"{cc} {func_name}({', '.join(['arg']*arg_count)}) -> {ret_kind}"
                normalized = self._normalize_signature(func_name, cc, param_positions, ret_kind)
                results.append({"name": func_name, "proto": proto_est, "source": "inferred", "args": arg_count, "cc": cc, "ret": ret_kind, "arg_locs": param_positions, "normalized_proto": normalized})
            else:
                # x86: derive from positions
                arg_count_est = len(param_positions)
                # basic CC heuristic
                cc = "cdecl"
                if any(p in ("ecx","edx") for p in param_positions):
                    cc = "fastcall"
                elif ret_imm and ret_imm % 4 == 0:
                    cc = "stdcall"
                proto_est = f"{cc} {func_name}({', '.join(['arg']*arg_count_est)}) -> {ret_kind}"
                normalized = self._normalize_signature(func_name, cc, param_positions, ret_kind)
                results.append({"name": func_name, "proto": proto_est, "source": "inferred", "args": arg_count_est, "cc": cc, "ret": ret_kind, "arg_locs": param_positions, "normalized_proto": normalized})
        self.metadata["export_prototypes"] = results
        if results:
            for r in results:
                print(f"      * {r['normalized_proto']}")

    def _infer_export_prototypes_angr(self) -> None:
        print("    - [Prototype Inference] Angr Variable Recovery:")
        try:
            image_base = self.pe.OPTIONAL_HEADER.ImageBase
            results = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if not exp.name:
                        continue
                    func_name = exp.name.decode('utf-8', errors='ignore')
                    target = self._resolve_export_target(exp)
                    use_path = str(self.dll_path)
                    use_image_base = image_base
                    use_rva = exp.address
                    if target["module_path"] and target["rva"] is not None:
                        use_path = target["module_path"]
                        use_image_base = target["image_base"]
                        use_rva = target["rva"]
                    arg_count = 0
                    # Set/identify calling convention (priority Microsoft AMD64, x86 refined at Capstone layer based on register usage)
                    cc_name = 'win64' if self.pe.FILE_HEADER.Machine == MACHINE_AMD64 else 'unknown'
                    # unify param positions via Capstone normalized collector
                    pe_obj = pefile.PE(use_path)
                    with open(use_path, 'rb') as f:
                        bytes2 = f.read()
                    # return kind via quick Capstone scan
                    ret_kind = "unknown"
                    try:
                        arch = CS_ARCH_X86
                        is64 = (pe_obj.FILE_HEADER.Machine == MACHINE_AMD64)
                        mode = CS_MODE_64 if is64 else CS_MODE_32
                        md = Cs(arch, mode)
                        md.detail = True
                        try:
                            off2 = pe_obj.get_offset_from_rva(use_rva)
                            code2 = bytes2[off2 : off2 + 1024]
                        except Exception:
                            code2 = b""
                        for ins in md.disasm(code2, use_image_base + use_rva):
                            if ins.mnemonic == "mov" and len(ins.operands) >= 2:
                                dst = ins.operands[0]
                                src = ins.operands[1]
                                dst_reg = ins.reg_name(dst.reg) if dst.type == 1 else None
                                if dst_reg in ("eax","rax"):
                                    if src.type == 3:
                                        try:
                                            immv = src.imm
                                            if immv in (0,1):
                                                ret_kind = "bool"
                                            else:
                                                ret_kind = "int"
                                        except Exception:
                                            ret_kind = "int"
                                    elif src.type == 2:
                                        ret_kind = "ptr"
                                    elif src.type == 1:
                                        ret_kind = "int"
                            if ins.mnemonic.startswith("set") and ins.operands:
                                dst = ins.operands[0]
                                if dst.type == CS_OP_REG and ins.reg_name(dst.reg) == "al":
                                    ret_kind = "bool"
                            if ins.mnemonic == "movzx" and len(ins.operands) >= 2:
                                dst = ins.operands[0]
                                src = ins.operands[1]
                                if dst.type == CS_OP_REG and ins.reg_name(dst.reg) in ("eax","rax"):
                                    if src.type == CS_OP_REG and ins.reg_name(src.reg) == "al":
                                        ret_kind = "bool"
                            if ins.mnemonic == "lea" and len(ins.operands) >= 2:
                                dst = ins.operands[0]
                                dst_reg = ins.reg_name(dst.reg) if dst.type == 1 else None
                                if dst_reg in ("eax","rax"):
                                    ret_kind = "ptr"
                    except Exception:
                        ret_kind = "unknown"
                    locs = self._collect_param_positions(pe_obj, bytes2, use_image_base, use_rva)
                    arg_count = len(locs)
                    normalized = self._normalize_signature(func_name, cc_name, locs, ret_kind)
                    results.append({"name": func_name, "proto": f"{cc_name} {func_name}({', '.join(['arg']*arg_count)})", "source": "angr", "args": arg_count, "cc": cc_name, "arg_locs": locs, "normalized_proto": normalized})
            if results:
                self.metadata["export_prototypes_angr"] = results
                for r in results:
                    print(f"      * {r['normalized_proto']}")
            else:
                print("      [+] Could not recover any parameter location evidence (possibly pure forwarders/trampolines or optimization elimination)")
        except Exception as e:
            print(f"      [!] Angr prototype inference failed: {e}")

    def _scan_angr_path_vulnerabilities(self) -> None:
        print("    - [Deep Analysis] Angr Symbolic Execution Path Exploration:")
        if not HAVE_ANGR:
            print("      [!] angr not installed, skipping path exploration")
            return

        try:
            # Suppress excessive logging
            import logging
            logging.getLogger('angr').setLevel(logging.ERROR)
            
            proj = angr.Project(str(self.dll_path), auto_load_libs=False)
            
            # 1. Identify Banned Imports Addresses
            banned_import_addrs = {}
            # CLE imports dict: name -> Symbol/DllImport
            for name, sym in proj.loader.main_object.imports.items():
                # Use name from key if sym.name is missing
                func_name = getattr(sym, 'name', name)
                
                if func_name and func_name.encode() in BANNED_APIS:
                    # Try to get address
                    addr = getattr(sym, 'rebased_addr', None)
                    if addr is None:
                        addr = getattr(sym, 'linked_addr', None)
                    
                    if addr:
                        banned_import_addrs[addr] = func_name
            
            if not banned_import_addrs:
                print("      [+] No sensitive APIs found in import table, skipping path analysis")
                return
                
            print(f"      [+] Building Control Flow Graph (CFG) - Target: {len(banned_import_addrs)} sensitive imports...")
            # CFGFast is static analysis, much faster
            cfg = proj.analyses.CFGFast()
            
            # Resolve CFG nodes for banned imports
            banned_nodes = []
            for addr, name in banned_import_addrs.items():
                node = cfg.model.get_any_node(addr)
                if node:
                    banned_nodes.append((node, name))
            
            findings = []
            import networkx as nx

            # 2. Check Reachability from Exports
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                start_t = time.perf_counter()
                processed = 0
                # Analysis of all export functions
                max_exports = getattr(self, 'angr_max_exports', 0)  # 0 = No limit
                timeout_ms = getattr(self, 'angr_timeout_ms', 300000)  # 5 minutes timeout
                total_exports = len([e for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name])
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if not exp.name: continue
                    processed += 1
                    if max_exports > 0 and processed > max_exports:
                        break
                    if (time.perf_counter() - start_t) * 1000 >= timeout_ms:
                        print(f"      [!] Timeout, analyzed {processed}/{total_exports} exports")
                        break
                    # Show progress every 100 exports
                    if processed % 100 == 0:
                        print(f"      [*] Progress: {processed}/{total_exports} exports...")
                    func_name = exp.name.decode('utf-8')
                    # Calculate VA
                    exp_addr = self.pe.OPTIONAL_HEADER.ImageBase + exp.address
                    
                    export_node = cfg.model.get_any_node(exp_addr)
                    if not export_node:
                        continue
                        
                    # Check path to any banned node
                    for banned_node, banned_name in banned_nodes:
                        if (time.perf_counter() - start_t) * 1000 >= timeout_ms:
                            break
                        if nx.has_path(cfg.graph, export_node, banned_node):
                            try:
                                hops = nx.shortest_path_length(cfg.graph, export_node, banned_node)
                            except Exception:
                                hops = -1
                            path_info = f"Export '{func_name}' -> Banned API '{banned_name}' (Reachable, hops={hops})"
                            findings.append(path_info)
                            print(f"      [!!!] Path confirmed: {path_info}")
            # Show analysis statistics
            print(f"      [+] Analyzed {processed}/{total_exports} export functions")
                            
            self.metadata["angr_findings"] = findings
            if not findings:
                 print("      [+] No direct call paths from export functions to sensitive APIs found")
                 
        except Exception as e:
            print(f"      [!] Angr analysis interrupted: {e}")

    def _assess_hijack_risk(self) -> None:
        score = 10
        risks = []

        if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0080:
            score -= 5
            risks.append("Force Integrity checking is enabled")

        if self.dll_path.name.lower() in KNOWN_DLLS:
            score -= 4
            risks.append("Belongs to KnownDLLs list")

        is_signed = WinTrustVerifier.verify(str(self.dll_path))
        if is_signed:
            print("    - [Signature]: ✅ Valid Signature (Trusted)")
        else:
            print("    - [Signature]: ❌ No signature or invalid signature")

        self.metadata["hijack_score"] = score
        self.metadata["risk_factors"] = risks

    def _print_summary(self) -> None:
        score = self.metadata["hijack_score"]
        print(f"\n    - [Hijack Feasibility Assessment]: {score}/10")
        if score >= 8:
            print("      [+] Extreme: Suitable as a hijacking target")
        elif score >= 5:
            print("      [~] Medium: Some restrictions exist")
        else:
            print("      [-] Difficult: Strong protection measures exist")
            
        for r in self.metadata["risk_factors"]:
            print(f"      * {r}")


