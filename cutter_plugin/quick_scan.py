# -*- coding: utf-8 -*-
"""
LuoDllHack Quick Scan - 在 Cutter Python 控制台中快速分析

使用方法：
1. 在 Cutter 中打开目标二进制
2. 打开 Python 控制台 (View -> Python Console)
3. 运行: exec(open('path/to/quick_scan.py').read())

或者复制以下代码到控制台：
"""

import cutter
import sys
import os

# 设置 LuoDllHack 路径
LUODLLHACK_PATH = r"D:\code\LuoDllHack"  # 修改为你的 LuoDllHack 路径
if LUODLLHACK_PATH not in sys.path:
    sys.path.insert(0, LUODLLHACK_PATH)


def get_current_binary():
    """获取当前加载的二进制文件路径"""
    info = cutter.cmdj("ij")
    return info.get("core", {}).get("file", "")


def scan_dangerous_apis():
    """扫描危险 API 并在 Cutter 中标注"""
    binary_path = get_current_binary()
    if not binary_path:
        print("[!] No binary loaded")
        return []

    print(f"[*] Analyzing: {binary_path}")

    try:
        from luodllhack.core import RizinCore
        from luodllhack.analysis.taint import TaintEngine

        # 创建分析引擎
        print("[*] Initializing LuoDllHack...")
        rz = RizinCore(binary_path)
        engine = TaintEngine(rz)

        # 扫描危险 API
        print("[*] Scanning dangerous APIs...")
        dangerous = engine.get_dangerous_imports()

        findings = []
        for addr, api_info in dangerous.items():
            finding = {
                "address": addr,
                "api": api_info.get("name", "unknown"),
                "vuln_type": api_info.get("vuln_type", "UNKNOWN"),
                "severity": api_info.get("severity", "Medium"),
            }
            findings.append(finding)

            # 在 Cutter 中添加注释
            comment = f"[LuoDllHack] {finding['vuln_type']}: {finding['api']}"
            cutter.cmd(f'CC "{comment}" @ 0x{addr:x}')

            # 添加标记
            cutter.cmd(f"f luodllhack.{finding['vuln_type'].lower()}_{addr:x} @ 0x{addr:x}")

            print(f"  [+] 0x{addr:x}: {finding['api']} ({finding['vuln_type']})")

        print(f"[*] Found {len(findings)} dangerous API calls")
        return findings

    except ImportError as e:
        print(f"[!] LuoDllHack not available: {e}")
        print(f"[!] Make sure LUODLLHACK_PATH is correct: {LUODLLHACK_PATH}")
        return []
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return []


def verify_address(address=None):
    """
    验证指定地址的漏洞

    Args:
        address: 地址 (None 则使用当前地址)
    """
    if address is None:
        address = cutter.cmdj("sj")  # 当前 seek 地址

    binary_path = get_current_binary()
    if not binary_path:
        print("[!] No binary loaded")
        return None

    print(f"[*] Verifying address: 0x{address:x}")

    try:
        from luodllhack.core import RizinCore
        from luodllhack.analysis.taint import TaintEngine

        rz = RizinCore(binary_path)
        engine = TaintEngine(rz)

        # 1. 检查边界检查
        print("[*] Checking bounds...")
        bounds_result = check_bounds(rz, address)

        # 2. 污点分析
        print("[*] Analyzing taint...")
        # 找到包含此地址的函数
        func = rz.get_function_containing(address)

        result = {
            "address": address,
            "has_bounds_check": bounds_result.get("has_bounds_check", False),
            "function": func.name if func else "unknown",
            "confidence": 0.4,
            "evidence": [],
        }

        if bounds_result.get("has_bounds_check"):
            result["confidence"] -= 0.15
            result["evidence"].append("Bounds check found before call")
        else:
            result["confidence"] += 0.2
            result["evidence"].append("No bounds check detected")

        # 输出结果
        print(f"\n{'='*50}")
        print(f"Verification Result for 0x{address:x}")
        print(f"{'='*50}")
        print(f"Function: {result['function']}")
        print(f"Bounds Check: {'Yes' if result['has_bounds_check'] else 'No'}")
        print(f"Confidence: {result['confidence']:.0%}")
        print(f"Evidence:")
        for ev in result["evidence"]:
            print(f"  - {ev}")
        print(f"{'='*50}")

        # 添加注释
        status = "VERIFIED" if result["confidence"] > 0.5 else "LOW_CONF"
        comment = f"[LuoDllHack {status}] Confidence: {result['confidence']:.0%}"
        cutter.cmd(f'CC "{comment}" @ 0x{address:x}')

        return result

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return None


def check_bounds(rz, address):
    """检查边界检查模式"""
    func = rz.get_function_containing(address)
    if not func:
        return {"has_bounds_check": False, "note": "No containing function"}

    bounds_check_mnemonics = {'cmp', 'test'}
    conditional_jumps = {'ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle', 'je', 'jne'}

    checks_found = []

    for bb in func.blocks:
        instructions = list(bb.instructions)
        for i, insn in enumerate(instructions):
            if insn.address >= address:
                break
            if insn.mnemonic.lower() in bounds_check_mnemonics:
                for j in range(i + 1, min(i + 5, len(instructions))):
                    if instructions[j].mnemonic.lower() in conditional_jumps:
                        checks_found.append({
                            "cmp_addr": hex(insn.address),
                            "cmp": f"{insn.mnemonic} {insn.operands}",
                            "jump": f"{instructions[j].mnemonic} {instructions[j].operands}",
                        })
                        break

    return {
        "has_bounds_check": len(checks_found) > 0,
        "checks": checks_found,
    }


def analyze_function(func_name=None):
    """
    分析指定函数

    Args:
        func_name: 函数名 (None 则使用当前函数)
    """
    if func_name is None:
        # 获取当前函数
        func_info = cutter.cmdj("afij")
        if func_info:
            func_name = func_info[0].get("name", "")

    if not func_name:
        print("[!] No function specified or found")
        return

    print(f"[*] Analyzing function: {func_name}")

    # 获取函数地址
    func_addr = cutter.cmd(f"?v {func_name}").strip()
    if not func_addr or func_addr == "0x0":
        print(f"[!] Function not found: {func_name}")
        return

    addr = int(func_addr, 16)

    # 获取函数中的所有调用
    cutter.cmd(f"s {func_addr}")
    calls = cutter.cmdj("afcj") or []

    print(f"[*] Found {len(calls)} calls in function")

    # 检查每个调用
    dangerous_calls = []
    DANGEROUS_APIS = {
        'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets',
        'memcpy', 'memmove', 'strncpy', 'strncat',
        'scanf', 'sscanf', 'fscanf',
        'read', 'recv', 'recvfrom',
        'malloc', 'realloc', 'free',
    }

    for call in calls:
        call_name = call.get("name", "").lower()
        for api in DANGEROUS_APIS:
            if api in call_name:
                dangerous_calls.append({
                    "address": call.get("addr", 0),
                    "target": call.get("name", ""),
                    "type": api,
                })
                break

    if dangerous_calls:
        print(f"\n[!] Found {len(dangerous_calls)} dangerous calls:")
        for dc in dangerous_calls:
            print(f"  0x{dc['address']:x}: {dc['target']}")
            verify_address(dc['address'])
    else:
        print("[*] No dangerous API calls found in this function")


def show_help():
    """显示帮助"""
    print("""
LuoDllHack Cutter Quick Scan
========================

Available functions:

  scan_dangerous_apis()
      Scan all dangerous API imports and mark them in Cutter

  verify_address(address=None)
      Verify a specific address (default: current address)
      Example: verify_address(0x401000)

  analyze_function(func_name=None)
      Analyze a specific function (default: current function)
      Example: analyze_function("main")

  check_bounds(rz, address)
      Check if there's bounds checking before an address

  show_help()
      Show this help message
""")


# 自动运行时显示帮助
if __name__ == "__main__" or True:
    print("[*] LuoDllHack Quick Scan loaded")
    print("[*] Type show_help() for available commands")
    print("[*] Quick start: scan_dangerous_apis()")
