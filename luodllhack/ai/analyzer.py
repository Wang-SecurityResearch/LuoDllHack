# -*- coding: utf-8 -*-
"""
luodllhack/ai/analyzer.py - LLM-Assisted Analysis

Uses LLM for:
- Code semantic analysis
- Vulnerability pattern recognition
- Reverse engineering assistance
"""

import os
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

from disasm.engine import DisasmEngine, Instruction, Function

try:
    import google.generativeai as genai
    HAVE_GENAI = True
except ImportError:
    HAVE_GENAI = False

# Import configuration
try:
    from luodllhack.core.config import default_config, LuoDllHackConfig
    HAVE_CONFIG = True
except ImportError:
    HAVE_CONFIG = False
    default_config = None
    LuoDllHackConfig = None


class AIAnalyzer:
    """
    LLM-Assisted Analyzer

    Features:
    - Analyze functionality of disassembled code
    - Identify potential vulnerability patterns
    - Assist in reverse engineering understanding

    Usage:
        ai = AIAnalyzer(engine)

        # Analyze function functionality
        result = ai.analyze_function(0x10001000)

        # Explain code snippet
        result = ai.explain_code(instructions)

        # Vulnerability analysis
        result = ai.analyze_vulnerability(address, vuln_type)
    """

    def __init__(self, engine: DisasmEngine, api_key: str = None, config: 'LuoDllHackConfig' = None):
        self.engine = engine
        self.config = config or (default_config if HAVE_CONFIG else None)

        # Get API Key from config or environment variable
        if api_key:
            self.api_key = api_key
        elif self.config and self.config.ai_api_key:
            self.api_key = self.config.ai_api_key
        else:
            self.api_key = os.environ.get("GEMINI_API_KEY", "")

        # Get model parameters from config
        if self.config:
            self.model_name = self.config.ai_model
            self.temperature = self.config.ai_temperature
        else:
            self.model_name = 'gemini-2.5-flash'
            self.temperature = 0.1

        if HAVE_GENAI and self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(
                self.model_name,
                generation_config=genai.GenerationConfig(
                    temperature=self.temperature
                )
            )
        else:
            self.model = None

    def is_available(self) -> bool:
        """Check if AI is available"""
        return self.model is not None

    def analyze_function(self, address: int) -> Dict[str, Any]:
        """
        Analyze function functionality

        Args:
            address: Function address

        Returns:
            Analysis result
        """
        if not self.is_available():
            return {"error": "AI not available"}

        func = self.engine.disasm_function(address)
        disasm_text = self._format_function(func)

        prompt = f"""
You are a professional reverse engineer. Please analyze the following x86-64 disassembly code and determine the purpose of this function.

Function Name: {func.name}
Address: 0x{func.address:x}
Functions Called: {', '.join(self.engine.imports.get(addr, f'sub_{addr:x}') for addr in func.calls)}

Disassembly Code:
```
{disasm_text}
```

Please analyze:
1. **Function Purpose**: What does this function do?
2. **Parameter Analysis**: What parameters does the function likely receive?
3. **Return Value**: What does the function return?
4. **Security Risks**: Are there any potential security issues?
5. **Recommended Naming**: What is a suggested function name?

Please answer in English with a clear format.
"""

        try:
            response = self.model.generate_content(prompt)
            return {
                "function": func.name,
                "address": f"0x{func.address:x}",
                "analysis": response.text if response.text else "Analysis failed"
            }
        except Exception as e:
            return {"error": str(e)}

    def explain_code(self, instructions: List[Instruction]) -> Dict[str, Any]:
        """
        Explain code snippet

        Args:
            instructions: List of instructions

        Returns:
            Explanation result
        """
        if not self.is_available():
            return {"error": "AI not available"}

        code_text = "\n".join(str(insn) for insn in instructions)

        prompt = f"""
Please explain the meaning of the following x86-64 assembly code line by line:

```
{code_text}
```

For each instruction, please explain:
1. What this instruction does
2. Registers/memory involved
3. Role in the overall logic

Please answer in English.
"""

        try:
            response = self.model.generate_content(prompt)
            return {
                "instruction_count": len(instructions),
                "explanation": response.text if response.text else "Explanation failed"
            }
        except Exception as e:
            return {"error": str(e)}

    def analyze_vulnerability(self, address: int, vuln_type: str,
                              context_size: int = 15,
                              verify_result: Dict = None,
                              full_function: bool = True,
                              taint_info: Dict = None,
                              xrefs: List[str] = None,
                              strings: List[str] = None) -> Dict[str, Any]:
        """
        Analyze potential vulnerability (Enhanced version, supports dynamic verification results and rich context)

        Args:
            address: Vulnerability address
            vuln_type: Vulnerability type
            context_size: Context size
            verify_result: Speakeasy verification result (optional)
            full_function: Whether to get full function disassembly
            taint_info: Taint analysis information (optional)
            xrefs: List of cross-references (optional)
            strings: List of strings referenced by the function (optional)

        Returns:
            Analysis result
        """
        if not self.is_available():
            return {"error": "AI not available"}

        # Get code context
        func_info = ""
        if full_function:
            try:
                func = self.engine.disasm_function(address)
                code_text = self._format_instructions(func.instructions, highlight=address)
                func_info = f"Function: sub_{func.address:x} (Size: {func.size} bytes, {len(func.instructions)} instructions)"
            except (ValueError, AttributeError, KeyError):
                # Fallback to context if full function disassembly fails
                context = self.engine.get_context(address, before=context_size, after=context_size)
                code_text = self._format_instructions(context, highlight=address)
                func_info = "(Showing context code only)"
        else:
            context = self.engine.get_context(address, before=context_size, after=context_size)
            code_text = self._format_instructions(context, highlight=address)

        # Build additional context information
        extra_context = ""
        
        if xrefs:
            extra_context += f"\n## Call Context (Xrefs)\nThis function is called from:\n"
            for ref in xrefs[:5]:
                extra_context += f"- {ref}\n"
            if len(xrefs) > 5:
                extra_context += f"... ({len(xrefs)} total callers)\n"

        if strings:
            extra_context += f"\n## String References\nStrings referenced in function:\n"
            for s in strings[:10]:
                extra_context += f"- {s}\n"

        if taint_info:
            extra_context += f"\n## Static Taint Analysis\n"
            if taint_info.get('found', False):
                extra_context += f"- **Taint Path**: Found ({len(taint_info.get('steps', []))} steps)\n"
                extra_context += f"- **Source**: {taint_info.get('source', 'Unknown')}\n"
                extra_context += f"- **Sink**: {taint_info.get('sink', 'Unknown')}\n"
            else:
                extra_context += "- **Taint Path**: No complete path found\n"

        # Build verification result information
        verify_info = ""
        if verify_result:
            verified = verify_result.get('verified', False)
            confidence = verify_result.get('confidence', 0)
            events = verify_result.get('events', [])
            
            verify_info = f"""
## Dynamic Verification Results (Speakeasy Emulator)
- **Verified**: {'Yes ✓' if verified else 'No'}
- **Confidence**: {confidence:.0%}
- **Detection Events**: {len(events)}
"""
            if events:
                for i, event in enumerate(events, 1):
                    evt_type = event.get('vuln_type', 'N/A') if isinstance(event, dict) else getattr(event, 'vuln_type', 'N/A')
                    evt_addr = event.get('address', 0) if isinstance(event, dict) else getattr(event, 'address', 0)
                    evt_mem = event.get('memory_addr', 0) if isinstance(event, dict) else getattr(event, 'memory_addr', 0)
                    evt_detail = event.get('details', '') if isinstance(event, dict) else getattr(event, 'details', '')
                    evt_seq = event.get('trigger_sequence', []) if isinstance(event, dict) else getattr(event, 'trigger_sequence', [])
                    
                    verify_info += f"""
### Event {i}: {evt_type}
- Trigger Address: 0x{evt_addr:x}
- Memory Address: 0x{evt_mem:x}
- Details: {evt_detail}
"""
                    if evt_seq:
                        verify_info += "Reproduction Steps:\n"
                        for step in evt_seq:
                            verify_info += f"  {step}\n"

        prompt = f"""
You are a senior binary vulnerability analysis expert. Please analyze the following **{vuln_type}** vulnerability based on static code, dynamic verification results, and context information.

## Basic Information
- Target Address: 0x{address:x} (marked with >>>)
- Binary File: {self.engine.binary_path.name}
- Architecture: {self.engine.arch}
- {func_info}
{extra_context}
{verify_info}

## Disassembly Code
```asm
{code_text}
```

Please perform an in-depth analysis based on the above information:

### 1. Vulnerability Confirmation
Confirm whether a {vuln_type} vulnerability exists by combining context information (e.g., call origins, string semantics) and dynamic verification results.

### 2. Root Cause
What is the code logic problem that leads to this vulnerability? Point out the specifically problematic instructions. If taint information is provided, combine it with path analysis.

### 3. Trigger Conditions
- What inputs/parameters are needed?
- What preconditions must be met?
- Do string references suggest a specific input format?

### 4. Exploit Analysis
- What exploit primitives can be obtained? (Arbitrary read/write/execute)
- Evaluation of exploitation difficulty.

### 5. Impact Assessment
- Severity: Critical/High/Medium/Low
- CWE Number
- Estimated CVSS Score

### 6. Remediation
Specific code-level remediation suggestions.

Please answer in English. If dynamic verification has confirmed the vulnerability, focus on exploitation methods and remediation plans.
"""

        try:
            response = self.model.generate_content(prompt)
            return {
                "address": f"0x{address:x}",
                "vuln_type": vuln_type,
                "verified": verify_result.get('verified') if verify_result else None,
                "confidence": verify_result.get('confidence') if verify_result else None,
                "analysis": response.text if response.text else "Analysis failed"
            }
        except Exception as e:
            return {"error": str(e)}

    def suggest_function_name(self, address: int) -> str:
        """Suggest function name"""
        if not self.is_available():
            return f"sub_{address:x}"

        func = self.engine.disasm_function(address)
        calls = [self.engine.imports.get(addr, "") for addr in func.calls]
        calls = [c for c in calls if c]

        if not calls:
            return f"sub_{address:x}"

        prompt = f"""
Based on the APIs called by the following function, suggest an appropriate function name:

Called APIs: {', '.join(calls[:10])}

Return only the function name and nothing else. Use snake_case format.
"""

        try:
            response = self.model.generate_content(prompt)
            if response.text:
                name = response.text.strip().replace(" ", "_")
                # Cleanup
                name = ''.join(c for c in name if c.isalnum() or c == '_')
                return name[:50] if name else f"sub_{address:x}"
        except Exception:
            # Drop back to default naming if AI API call fails
            pass

        return f"sub_{address:x}"

    def interactive_analysis(self, question: str,
                             context: Dict[str, Any] = None) -> str:
        """
        Interactive analysis Q&A

        Args:
            question: User's question
            context: Context information

        Returns:
            Answer
        """
        if not self.is_available():
            return "AI not available, please set GEMINI_API_KEY"

        context_str = ""
        if context:
            # Optimize context display
            context_str = "\nCurrent Context:\n"
            for k, v in context.items():
                if k == "code_snippet":
                    context_str += f"Code Snippet:\n```asm\n{v}\n```\n"
                elif k == "strings":
                    context_str += f"String References: {v}\n"
                else:
                    context_str += f"{k}: {v}\n"

        prompt = f"""
You are a professional reverse engineering and binary security expert. The user is analyzing a binary file using disassembly tools.

{context_str}

User's Question: {question}

Please answer in English, providing professional and accurate help. If the question involves code analysis, please cite code snippets from the context.
"""

        try:
            response = self.model.generate_content(prompt)
            return response.text if response.text else "Unable to generate answer"
        except Exception as e:
            return f"Error: {e}"

    def _format_function(self, func: Function) -> str:
        """Format function disassembly"""
        lines = []
        for insn in func.instructions[:100]:  # Limit length
            lines.append(str(insn))
        if len(func.instructions) > 100:
            lines.append(f"... ({len(func.instructions) - 100} more instructions)")
        return "\n".join(lines)

    def _format_instructions(self, instructions: List[Instruction],
                             highlight: int = None) -> str:
        """Format instruction list"""
        lines = []
        for insn in instructions:
            prefix = ">>> " if insn.address == highlight else "    "
            lines.append(f"{prefix}{insn}")
        return "\n".join(lines)
