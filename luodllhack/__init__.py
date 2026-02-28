# -*- coding: utf-8 -*-
"""
LuoDllHack - Automated Vulnerability Mining & Exploitation Framework v5.2.0

Unified architecture integrating four core capabilities:
1. Vulnerability Mining (analysis) - Taint analysis, Symbolic execution, CFG, Data flow
2. Vulnerability Verification (verify) - Dynamic verification, Confidence scoring
3. DLL Hijacking (dll_hijack) - Proxy generation, Compilation, Verification
4. Vulnerability Exploitation (exploit) - Shellcode/ROP/Encoder/SEH/Egghunter

Auxiliary Modules:
- ai: AI-driven vulnerability mining (ReAct Agent Network architecture)
- ai/agents: Agent Network framework (NetworkRunner + specialized Agents)
- symbolic: Symbolic execution enhancements
- memory: Memory lifecycle tracking
- core: Unified type definitions and configuration

v5.2.0 New Features:
- ReAct Agent Network: Decentralized multi-agent collaboration architecture
- NetworkRunner: Unified agent network manager
- MCP-style tools: Standardized tool calling interface
- Agent autonomous reasoning: Think-Act-Observe loop

v5.1.0 Features:
- EXP Generator: Complete exploit chain with Shellcode/ROP chain/Encoder/Egghunter
- Multi-architecture support: x86/x64 Windows Shellcode (reverse/bind shell)
- DEP Bypass: VirtualProtect/VirtualAlloc/WriteProcessMemory ROP chains
- OSED Certification Support: Covers all exploit techniques required for the exam

v5.0.0 Features:
- Multi-LLM Backend Support: Gemini / OpenAI / Ollama / Anthropic
- Parallel Execution: ThreadPoolExecutor + LLM client pool
- Message Bus: Real-time communication and collaboration between agents
"""

__version__ = "5.2.0"
__author__ = "LuoDllHack Team"

import types

# =============================================================================
# Core Module Imports
# =============================================================================

try:
    from . import core
except BaseException as e:
    print(f"[!] Critical: Failed to import core module: {e}")
    raise

try:
    from . import symbolic
except BaseException as e:
    print(f"[!] Warning: Failed to import symbolic module: {e}")

try:
    from . import memory
except BaseException as e:
    print(f"[!] Warning: Failed to import memory module: {e}")

try:
    from . import exploit
except BaseException as e:
    print(f"[!] Warning: Failed to import exploit module: {e}")

try:
    import ctf_toolkit
except BaseException as e:
    print(f"[!] Warning: Failed to import ctf_toolkit module: {e}")

# Deferred import of analysis modules (due to dependencies)
def _import_analysis() -> types.ModuleType:
    try:
        from . import analysis
        return analysis
    except Exception as e:
        print(f"[!] Warning: Failed to import analysis module: {e}")
        return None

def _import_verify() -> types.ModuleType:
    try:
        from . import verify
        return verify
    except Exception as e:
        print(f"[!] Warning: Failed to import verify module: {e}")
        return None

def _import_dll_hijack() -> types.ModuleType:
    try:
        from . import dll_hijack
        return dll_hijack
    except Exception as e:
        print(f"[!] Warning: Failed to import dll_hijack module: {e}")
        return None

def _import_ai() -> types.ModuleType:
    try:
        from . import ai
        return ai
    except Exception as e:
        print(f"[!] Warning: Failed to import ai module: {e}")
        return None

# =============================================================================
# Unified Type Exports
# =============================================================================

from .core.types import (
    VulnType,
    SourceType,
    PointerState,
    TaintSource,
    TaintSink,
    TaintPath,
    VulnFinding,
    ConfidenceScore,
    ScoredFinding,
)

from .core.config import LuoDllHackConfig, default_config

# =============================================================================
# Capability Detection
# =============================================================================

def get_capabilities() -> dict:
    """Get currently available capabilities"""
    caps = {
        'analysis': {},
        'verify': {},
        'dll_hijack': {},
        'ai': {},
        'multi_agent': {},  # [v5.0] Multi-agent collaboration capability
        'zeroday': {},
    }

    # Detect analysis capabilities
    try:
        from .analysis import taint
        caps['analysis']['taint_engine'] = True
    except (ImportError, AttributeError):
        caps['analysis']['taint_engine'] = False

    try:
        from .analysis import cfg
        caps['analysis']['cfg_builder'] = True
    except (ImportError, AttributeError):
        caps['analysis']['cfg_builder'] = False

    try:
        from .analysis import dataflow
        caps['analysis']['dataflow'] = True
    except (ImportError, AttributeError):
        caps['analysis']['dataflow'] = False

    try:
        from .symbolic import executor
        caps['analysis']['symbolic'] = True
    except (ImportError, AttributeError):
        caps['analysis']['symbolic'] = False

    try:
        from .memory import lifecycle
        caps['analysis']['memory'] = True
    except (ImportError, AttributeError):
        caps['analysis']['memory'] = False

    # [New] Detect 0day discovery capabilities
    try:
        from .analysis.neuro_symbolic import ZeroDayDiscoveryEngine
        caps['zeroday']['neuro_symbolic'] = True
    except (ImportError, AttributeError):
        caps['zeroday']['neuro_symbolic'] = False

    try:
        from .analysis.pattern_learning import AdvancedVulnerabilityMiner
        caps['zeroday']['pattern_learning'] = True
    except (ImportError, AttributeError):
        caps['zeroday']['pattern_learning'] = False

    try:
        from .exploit.intelligent_fuzzing import HybridAnalysisEngine
        caps['zeroday']['hybrid_analysis'] = True
    except (ImportError, AttributeError):
        caps['zeroday']['hybrid_analysis'] = False

    # Detect verification capabilities
    try:
        from .verify import speakeasy
        caps['verify']['speakeasy'] = True
    except (ImportError, AttributeError):
        caps['verify']['speakeasy'] = False

    try:
        from .analysis.taint import ConfidenceScorer
        caps['verify']['confidence'] = True
    except (ImportError, AttributeError):
        caps['verify']['confidence'] = False

    try:
        from .exploit import validator
        caps['verify']['poc_validator'] = True
    except (ImportError, AttributeError):
        caps['verify']['poc_validator'] = False

    # Detect DLL hijacking capabilities
    try:
        from .dll_hijack import generator
        caps['dll_hijack']['generator'] = True
    except (ImportError, AttributeError):
        caps['dll_hijack']['generator'] = False

    try:
        from .dll_hijack import compiler
        caps['dll_hijack']['compiler'] = True
    except (ImportError, AttributeError):
        caps['dll_hijack']['compiler'] = False

    try:
        from .dll_hijack import validator
        caps['dll_hijack']['validator'] = True
    except (ImportError, AttributeError):
        caps['dll_hijack']['validator'] = False

    # Detect AI capabilities
    try:
        from .ai import agent
        caps['ai']['agent'] = True
    except (ImportError, AttributeError):
        caps['ai']['agent'] = False

    try:
        from .ai import security
        caps['ai']['security'] = True
    except (ImportError, AttributeError):
        caps['ai']['security'] = False

    try:
        from .ai import analyzer
        caps['ai']['analyzer'] = True
    except (ImportError, AttributeError):
        caps['ai']['analyzer'] = False

    # [v5.0] Detect multi-agent collaboration capabilities
    try:
        from .ai.agents import HAVE_MULTI_AGENT
        caps['multi_agent']['available'] = HAVE_MULTI_AGENT
    except (ImportError, AttributeError):
        caps['multi_agent']['available'] = False

    try:
        from .ai.agents import NetworkRunner
        caps['multi_agent']['network_runner'] = True
    except (ImportError, AttributeError):
        caps['multi_agent']['network_runner'] = False

    try:
        from .ai.agents import MessageBus, SharedState, AgentRegistry
        caps['multi_agent']['message_bus'] = True
        caps['multi_agent']['shared_state'] = True
        caps['multi_agent']['agent_registry'] = True
    except (ImportError, AttributeError):
        caps['multi_agent']['message_bus'] = False
        caps['multi_agent']['shared_state'] = False
        caps['multi_agent']['agent_registry'] = False

    try:
        from .ai.agents import LLMClientPool
        caps['multi_agent']['llm_pool'] = True
    except (ImportError, AttributeError):
        caps['multi_agent']['llm_pool'] = False

    try:
        from .ai.agents import (
            AnalyzerAgent, ExploiterAgent, CriticAgent,
            ValidationAgent,
        )
        caps['multi_agent']['agents'] = {
            'analyzer': True,
            'exploiter': True,
            'critic': True,
            'validation': True,
        }
    except (ImportError, AttributeError):
        caps['multi_agent']['agents'] = {
            'analyzer': False,
            'exploiter': False,
            'critic': False,
            'validation': False,
        }

    # Detect multi-LLM backend support
    try:
        from .ai.agents import GeminiBackend
        caps['multi_agent']['backend_gemini'] = True
    except (ImportError, AttributeError):
        caps['multi_agent']['backend_gemini'] = False

    try:
        from .ai.agents import OpenAIBackend
        caps['multi_agent']['backend_openai'] = True
    except (ImportError, AttributeError):
        caps['multi_agent']['backend_openai'] = False

    try:
        from .ai.agents import OllamaBackend
        caps['multi_agent']['backend_ollama'] = True
    except (ImportError, AttributeError):
        caps['multi_agent']['backend_ollama'] = False

    try:
        from .ai.agents import AnthropicBackend
        caps['multi_agent']['backend_anthropic'] = True
    except (ImportError, AttributeError):
        caps['multi_agent']['backend_anthropic'] = False

    return caps


def print_banner() -> None:
    """Print LuoDllHack Banner"""
    banner = r"""
================================================================
     _                       ____  _ _ _   _            _
    | |   _   _  ___        |  _ \| | | | | | __ _  ___| | __
    | |  | | | |/ _ \       | | | | | | |_| |/ _` |/ __| |/ /
    | |__| |_| | (_) |      | |_| | | |  _  | (_| | (__|   <
    |_____\__,_|\___/  _____|____/|_|_|_| |_|\__,_|\___|_|\_\
                      |_____|

    Automated Vulnerability Mining & Exploitation Framework
                        v5.1.0
    [NEW] EXP Generator | Shellcode | ROP Chain | OSED Ready
================================================================
"""
    print(banner)


# =============================================================================
# Convenient Imports
# =============================================================================

# Vulnerability Mining
TaintEngine = None
VulnAnalyzer = None
CFGBuilder = None
DataFlowAnalyzer = None

# [New] 0day Discovery Engines
ZeroDayDiscoveryEngine = None
AdvancedVulnerabilityMiner = None
HybridAnalysisEngine = None

# Vulnerability Verification
SpeakeasyVerifier = None
ConfidenceScorer = None

# DLL Hijacking
ProxyGenerator = None
PEParser = None

# AI Analysis
VulnHuntingAgent = None
SecurityAnalyzer = None

# PoC Generation
try:
    from .exploit import PoCGenerator, PayloadBuilder
except BaseException:
    PoCGenerator = None
    PayloadBuilder = None


def _lazy_load() -> None:
    """Deferred loading of core classes"""
    global TaintEngine, VulnAnalyzer, CFGBuilder, DataFlowAnalyzer
    global ZeroDayDiscoveryEngine, AdvancedVulnerabilityMiner, HybridAnalysisEngine
    global SpeakeasyVerifier, ConfidenceScorer
    global ProxyGenerator, PEParser
    global VulnHuntingAgent, SecurityAnalyzer

    try:
        from .analysis import TaintEngine, VulnAnalyzer, CFGBuilder, DataFlowAnalyzer
    except BaseException:
        pass

    # [New] Load 0day discovery engines
    try:
        from .analysis import ZeroDayDiscoveryEngine, AdvancedVulnerabilityMiner
        from .exploit import HybridAnalysisEngine
    except BaseException:
        pass

    try:
        from .verify import SpeakeasyVerifier, ConfidenceScorer
    except BaseException:
        pass

    try:
        from .dll_hijack import ProxyGenerator, PEParser
    except BaseException:
        pass

    try:
        from .ai import VulnHuntingAgent, SecurityAnalyzer
    except BaseException:
        pass


__all__ = [
    # Modules
    'core', 'symbolic', 'memory', 'exploit',
    # Types
    'VulnType', 'SourceType', 'PointerState',
    'TaintSource', 'TaintSink', 'TaintPath', 'VulnFinding',
    'ConfidenceScore', 'ScoredFinding',
    # Configuration
    'LuoDllHackConfig', 'default_config',
    # Utility Functions
    'get_capabilities', 'print_banner',
]
