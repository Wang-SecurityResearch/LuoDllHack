# -*- coding: utf-8 -*-
"""
luodllhack/ai/tools/definitions.py
Tool Definitions - All tool schemas callable by LLM

Extracted from registry.py, defines tools':
- Name
- Description
- Parameter schema
"""

from typing import Dict, List, Any

# =============================================================================
# Tool Definitions
# =============================================================================

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    # 1. Disassembly tool
    {
        "name": "disassemble_function",
        "description": "Disassemble the function at the specified address and return assembly code",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hexadecimal, e.g., '0x10001000')"
                },
                "max_instructions": {
                    "type": "integer",
                    "description": "Maximum number of instructions (default 50)"
                }
            },
            "required": ["address"]
        }
    },

    # 2. Taint analysis tool
    {
        "name": "analyze_taint_flow",
        "description": "Analyze the taint flow of a function to check if parameters can reach dangerous sinks",
        "parameters": {
            "type": "object",
            "properties": {
                "func_address": {
                    "type": "string",
                    "description": "Function address (hexadecimal)"
                },
                "func_name": {
                    "type": "string",
                    "description": "Function name"
                }
            },
            "required": ["func_address", "func_name"]
        }
    },

    # 3. Cross-function analysis tool
    {
        "name": "analyze_cross_function",
        "description": "Perform cross-function taint analysis to track vulnerabilities in internal call chains",
        "parameters": {
            "type": "object",
            "properties": {
                "exports": {
                    "type": "object",
                    "description": "Dictionary of export functions {name: address}"
                }
            },
            "required": ["exports"]
        }
    },

    # 4. Dangerous API check
    {
        "name": "check_dangerous_imports",
        "description": "Check for dangerous API functions imported by the DLL",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },

    # 5. Call chain analysis
    {
        "name": "find_path_to_sink",
        "description": "Find call paths from export functions to dangerous sinks",
        "parameters": {
            "type": "object",
            "properties": {
                "export_name": {
                    "type": "string",
                    "description": "Export function name"
                },
                "sink_name": {
                    "type": "string",
                    "description": "Target sink name (e.g., 'strcpy')"
                }
            },
            "required": ["export_name", "sink_name"]
        }
    },

    # 6. PoC generation tool
    {
        "name": "generate_poc",
        "description": "Generate Python PoC code based on vulnerability information. IMPORTANT: The generated code is properly escaped. Use verify_poc directly, and do NOT manually modify the code (especially string escaping).",
        "parameters": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "enum": ["buffer_overflow", "format_string", "command_injection",
                             "path_traversal", "integer_overflow", "double_free", "use_after_free"],
                    "description": "Vulnerability type"
                },
                "target_export": {
                    "type": "string",
                    "description": "Target export function name"
                },
                "payload_hint": {
                    "type": "string",
                    "description": "Payload hint (e.g., 'overflow size 256')"
                },
                "sink_address": {
                    "type": "string",
                    "description": "Address of the dangerous sink, used for symbolic execution to solve for precise trigger input"
                }
            },
            "required": ["vuln_type", "target_export"]
        }
    },

    # 7. PoC verification tool
    {
        "name": "verify_poc",
        "description": "Verify in a sandbox if the PoC can trigger a crash",
        "parameters": {
            "type": "object",
            "properties": {
                "poc_code": {
                    "type": "string",
                    "description": "Python PoC code"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout (seconds)"
                }
            },
            "required": ["poc_code"]
        }
    },

    # 8. Verify last generated PoC
    {
        "name": "verify_last_poc",
        "description": "Verify the most recently generated PoC (no need to pass poc_code, reduces context token consumption)",
        "parameters": {
            "type": "object",
            "properties": {
                "timeout": {
                    "type": "integer",
                    "description": "Timeout (seconds)"
                }
            },
            "required": []
        }
    },

    # 9. Symbolic execution solver
    {
        "name": "solve_input",
        "description": "Use symbolic execution to solve for specific input that triggers the vulnerability",
        "parameters": {
            "type": "object",
            "properties": {
                "source_addr": {
                    "type": "string",
                    "description": "Source address of taint"
                },
                "sink_addr": {
                    "type": "string",
                    "description": "Sink address"
                }
            },
            "required": ["source_addr", "sink_addr"]
        }
    },

    # 10. Get algorithm analysis results
    {
        "name": "get_algorithm_findings",
        "description": "Retrieve vulnerabilities found by static analysis algorithms for cross-validation. Returns findings such as taint analysis, memory vulnerabilities, integer overflows, etc.",
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["all", "taint_paths", "memory_vulns", "integer_overflows",
                             "cross_function_uaf", "summary"],
                    "description": "Category of findings to retrieve (default 'all')"
                }
            },
            "required": []
        }
    },

    # 11. Validate algorithm finding
    {
        "name": "validate_algorithm_finding",
        "description": "Perform secondary validation on a vulnerability found by the algorithm to determine if it's a real vulnerability",
        "parameters": {
            "type": "object",
            "properties": {
                "finding_index": {
                    "type": "integer",
                    "description": "Index number of the finding"
                },
                "category": {
                    "type": "string",
                    "enum": ["taint_paths", "memory_vulns", "integer_overflows"],
                    "description": "Finding category"
                }
            },
            "required": ["finding_index", "category"]
        }
    },

    # =========================================================================
    # Enhanced Analysis Tools
    # =========================================================================

    # 12. Bounds check detection
    {
        "name": "check_bounds_before_sink",
        "description": "Detect if a bounds check exists before a dangerous sink call. If a valid bounds check exists, the vulnerability might be a false positive. Used to verify if vulnerabilities found by taint analysis are truly exploitable.",
        "parameters": {
            "type": "object",
            "properties": {
                "sink_address": {
                    "type": "string",
                    "description": "Address of the dangerous sink call (hexadecimal)"
                },
                "tainted_register": {
                    "type": "string",
                    "description": "Register containing the tainted data (e.g., 'rcx', 'rdx')"
                }
            },
            "required": ["sink_address", "tainted_register"]
        }
    },

    # 13. Pointer lifecycle analysis
    {
        "name": "analyze_pointer_lifecycle",
        "description": "Analyze the full lifecycle of pointers in a function to detect Use-After-Free and Double-Free vulnerabilities. Tracks all operations from allocation to release.",
        "parameters": {
            "type": "object",
            "properties": {
                "func_address": {
                    "type": "string",
                    "description": "Address of the function to analyze (hexadecimal)"
                },
                "func_name": {
                    "type": "string",
                    "description": "Function name"
                }
            },
            "required": ["func_address", "func_name"]
        }
    },

    # 14. Symbolic execution exploration
    {
        "name": "symbolic_explore",
        "description": "Use symbolic execution to explore from the function entry to the target sink, collect path constraints, and solve for precise input that triggers the vulnerability. This is a crucial step for generating reliable PoCs.",
        "parameters": {
            "type": "object",
            "properties": {
                "func_address": {
                    "type": "string",
                    "description": "Function entry address (hexadecimal)"
                },
                "target_sink_address": {
                    "type": "string",
                    "description": "Target sink address (hexadecimal)"
                },
                "num_args": {
                    "type": "integer",
                    "description": "Number of function arguments (default 4)"
                }
            },
            "required": ["func_address", "target_sink_address"]
        }
    },

    # 15. Comprehensive vulnerability verification
    {
        "name": "deep_verify_vulnerability",
        "description": "Perform deep verification of suspected vulnerabilities, combining multiple techniques such as bounds checking, lifecycle analysis, and symbolic execution to provide a confidence score.",
        "parameters": {
            "type": "object",
            "properties": {
                "sink_address": {
                    "type": "string",
                    "description": "Sink call address"
                },
                "vuln_type": {
                    "type": "string",
                    "enum": ["buffer_overflow", "format_string", "command_injection",
                             "use_after_free", "double_free", "integer_overflow"],
                    "description": "Vulnerability type"
                },
                "tainted_arg_index": {
                    "type": "integer",
                    "description": "Tainted argument index (0-based)"
                }
            },
            "required": ["sink_address", "vuln_type"]
        }
    },

    # 16. Batch verification of dangerous imports
    {
        "name": "verify_all_dangerous_imports",
        "description": "Automatically perform deep verification for all dangerous imported APIs to batch detect which might be real vulnerabilities. This is the best way to quickly screen, returning a confidence score for each API.",
        "parameters": {
            "type": "object",
            "properties": {
                "max_apis": {
                    "type": "integer",
                    "description": "Maximum number of APIs to verify (default 10)"
                }
            },
            "required": []
        }
    },
]


def get_tool_definition(name: str) -> Dict[str, Any]:
    """Get the definition of a specified tool"""
    for tool in TOOL_DEFINITIONS:
        if tool["name"] == name:
            return tool
    return None


def get_all_tool_names() -> List[str]:
    """Get all tool names"""
    return [tool["name"] for tool in TOOL_DEFINITIONS]
