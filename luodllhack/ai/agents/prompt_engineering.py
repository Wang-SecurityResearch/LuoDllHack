# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/prompt_engineering.py
Advanced Prompt Engineering

Provides few-shot examples, XML tag formatting, and other advanced prompt features
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json


@dataclass
class FewShotExample:
    """Few-shot example"""
    input: str
    output: str
    reasoning: Optional[str] = None


class PromptTemplate:
    """
    Prompt Template System
    
    Supports few-shot examples and XML tag formatting
    """
    
    def __init__(
        self,
        template: str,
        few_shot_examples: List[FewShotExample] = None,
        use_xml_tags: bool = True
    ):
        """
        Initialize template
        
        Args:
            template: Template string
            few_shot_examples: Few-shot examples
            use_xml_tags: Whether to use XML tags
        """
        self.template = template
        self.few_shot_examples = few_shot_examples or []
        self.use_xml_tags = use_xml_tags
    
    def format(self, **kwargs) -> str:
        """
        Format template
        
        Args:
            **kwargs: Template variables
            
        Returns:
            Formatted prompt
        """
        # Build few-shot section
        few_shot_section = ""
        if self.few_shot_examples:
            few_shot_section = self._build_few_shot_section()
        
        # Format main template
        prompt = self.template.format(**kwargs)
        
        # Add few-shot examples
        if few_shot_section:
            prompt = f"{few_shot_section}\n\n{prompt}"
        
        # Apply XML tags (if enabled)
        if self.use_xml_tags:
            prompt = self._apply_xml_tags(prompt, kwargs)
        
        return prompt
    
    def _build_few_shot_section(self) -> str:
        """Build few-shot example section"""
        if not self.few_shot_examples:
            return ""
        
        if self.use_xml_tags:
            examples_text = "<examples>\n"
            for i, example in enumerate(self.few_shot_examples, 1):
                examples_text += f"<example id=\"{i}\">\n"
                examples_text += f"<input>\n{example.input}\n</input>\n"
                examples_text += f"<output>\n{example.output}\n</output>\n"
                if example.reasoning:
                    examples_text += f"<reasoning>\n{example.reasoning}\n</reasoning>\n"
                examples_text += "</example>\n"
            examples_text += "</examples>"
            return examples_text
        else:
            examples_text = "# Examples:\n\n"
            for i, example in enumerate(self.few_shot_examples, 1):
                examples_text += f"## Example {i}:\n"
                examples_text += f"Input: {example.input}\n"
                examples_text += f"Output: {example.output}\n"
                if example.reasoning:
                    examples_text += f"Reasoning: {example.reasoning}\n"
                examples_text += "\n"
            return examples_text
    
    def _apply_xml_tags(self, prompt: str, kwargs: Dict) -> str:
        """Apply XML tag formatting"""
        # Automatically add XML tags based on specific keys in kwargs here
        # Simple implementation: do not modify the existing prompt
        return prompt


# ============================================================================
# Predefined Template Library
# ============================================================================

# Attack Surface Analysis Template (Improved)
ATTACK_SURFACE_ANALYSIS_TEMPLATE = PromptTemplate(
    template="""<task>
Analyze the attack surface of a DLL and prioritize targets for vulnerability research.
</task>

<dll_info>
<name>{dll_name}</name>
<exports>
{exports_list}
</exports>
<dangerous_imports>
{dangerous_imports}
</dangerous_imports>
</dll_info>

<instructions>
1. Identify the most promising functions for vulnerability research
2. Correlate exports with dangerous imports
3. Suggest exploitation strategies
4. Prioritize by risk level
</instructions>

<output_format>
Respond with valid JSON only, no markdown code blocks:
{{
    "high_priority_targets": [
        {{
            "function": "name",
            "reason": "why this is high priority",
            "suggested_vuln_types": ["list"],
            "risk_score": 0.0-1.0
        }}
    ],
    "attack_vectors": [
        {{
            "vector": "description",
            "entry_point": "function name",
            "dangerous_api": "api used",
            "exploitation_difficulty": "easy|medium|hard"
        }}
    ],
    "overall_assessment": "brief assessment",
    "recommended_order": ["ordered list of functions to analyze"]
}}
</output_format>
""",
    few_shot_examples=[
        FewShotExample(
            input="DLL: user_input.dll, Exports: ProcessUserData, Imports: strcpy, sprintf",
            output=json.dumps({
                "high_priority_targets": [{
                    "function": "ProcessUserData",
                    "reason": "Uses dangerous string functions with user input",
                    "suggested_vuln_types": ["BUFFER_OVERFLOW", "FORMAT_STRING"],
                    "risk_score": 0.9
                }],
                "attack_vectors": [{
                    "vector": "Buffer overflow via unchecked strcpy",
                    "entry_point": "ProcessUserData",
                    "dangerous_api": "strcpy",
                    "exploitation_difficulty": "easy"
                }],
                "overall_assessment": "High risk due to unsafe string handling",
                "recommended_order": ["ProcessUserData"]
            }, indent=2),
            reasoning="strcpy is known to be unsafe, especially with user input"
        )
    ],
    use_xml_tags=True
)


# Vulnerability Finding Review Template (Improved)
FINDING_REVIEW_TEMPLATE = PromptTemplate(
    template="""<task>
Review a vulnerability finding for validity and provide improvement suggestions.
</task>

<finding>
<type>{vuln_type}</type>
<severity>{severity}</severity>
<confidence>{confidence}</confidence>
<function>{function}</function>
<evidence>
{evidence}
</evidence>
</finding>

<context>
<entry_point_functions>DllMain, DllEntryPoint, _DllMainCRTStartup</entry_point_functions>
<well_audited_modules>chromium, openssl, webkit</well_audited_modules>
</context>

<instructions>
1. Assess if this is a true positive or false positive
2. Check for common FP patterns (entry points, well-audited code)
3. Evaluate evidence quality
4. Identify missing evidence
5. Suggest improvements
6. Rate overall quality (0.0-1.0)
</instructions>

<output_format>
{{
    "is_valid": true/false,
    "is_likely_fp": true/false,
    "fp_reasons": ["list of reasons if FP"],
    "evidence_quality": "strong|moderate|weak",
    "missing_evidence": ["list"],
    "improvements": ["list"],
    "quality_score": 0.0-1.0,
    "recommendation": "accept|reject|needs_more_evidence"
}}
</output_format>
""",
    few_shot_examples=[
        FewShotExample(
            input="Type: BUFFER_OVERFLOW, Function: DllMain, Confidence: 0.3",
            output=json.dumps({
                "is_valid": False,
                "is_likely_fp": True,
                "fp_reasons": ["Entry point function", "Low confidence", "Insufficient evidence"],
                "evidence_quality": "weak",
                "missing_evidence": ["Taint path", "PoC", "Crash info"],
                "improvements": ["Verify with deeper analysis", "Check if user input reaches this code"],
                "quality_score": 0.2,
                "recommendation": "reject"
            }, indent=2),
            reasoning="Entry point functions like DllMain rarely have exploitable buffer overflows"
        )
    ],
    use_xml_tags=True
)


# PoC Review Template
POC_REVIEW_TEMPLATE = PromptTemplate(
    template="""<task>
Review a Proof-of-Concept (PoC) code for a vulnerability.
</task>

<poc_code>
{poc_code}
</poc_code>

<vulnerability>
<type>{vuln_type}</type>
<target_function>{target_function}</target_function>
</vulnerability>

<instructions>
1. Check if the PoC is likely to work
2. Identify potential issues
3. Suggest improvements
4. Rate quality (0.0-1.0)
</instructions>

<output_format>
{{
    "likely_to_work": true/false,
    "issues": ["list of issues"],
    "improvements": ["list of improvements"],
    "quality_score": 0.0-1.0,
    "critical_issues": ["issues that would prevent execution"]
}}
</output_format>
""",
    few_shot_examples=[
        FewShotExample(
            input="PoC: payload = 'A' * 1000; call_function(payload)",
            output=json.dumps({
                "likely_to_work": False,
                "issues": ["No bad character handling", "No offset calculation", "No return address"],
                "improvements": [
                    "Use pattern to find offset",
                    "Detect bad characters",
                    "Calculate proper return address"
                ],
                "quality_score": 0.3,
                "critical_issues": ["Missing offset calculation"]
            }, indent=2)
        )
    ],
    use_xml_tags=True
)


# Function Risk Assessment Template
FUNCTION_RISK_TEMPLATE = PromptTemplate(
    template="""<task>
Assess the security risk of a function for vulnerability research.
</task>

<function>
<name>{function_name}</name>
<address>{address}</address>
<disassembly>
{disassembly}
</disassembly>
<called_apis>
{called_apis}
</called_apis>
</function>

<instructions>
1. Identify dangerous patterns
2. Check for potential vulnerabilities
3. Assess exploitability
4. Recommend analysis depth
</instructions>

<output_format>
{{
    "risk_level": "critical|high|medium|low",
    "risk_score": 0.0-1.0,
    "dangerous_patterns": ["list"],
    "potential_vulns": ["list"],
    "exploitability": "likely|possible|unlikely",
    "recommended_analysis": "deep|standard|skip",
    "reasoning": "brief explanation"
}}
</output_format>
""",
    few_shot_examples=[
        FewShotExample(
            input="Function: ProcessInput, APIs: strcpy, gets, sprintf",
            output=json.dumps({
                "risk_level": "critical",
                "risk_score": 0.95,
                "dangerous_patterns": ["Unsafe string functions", "No bounds checking"],
                "potential_vulns": ["BUFFER_OVERFLOW", "FORMAT_STRING"],
                "exploitability": "likely",
                "recommended_analysis": "deep",
                "reasoning": "Multiple dangerous APIs with no apparent safety checks"
            }, indent=2)
        )
    ],
    use_xml_tags=True
)


# Payload Optimization Template
OPTIMIZE_PAYLOAD_TEMPLATE = PromptTemplate(
    template="""<task>
Optimize the exploit payload for maximum reliability and effectiveness.
</task>

<vulnerability_details>
<type>{vuln_type}</type>
<target_function>{function}</target_function>
<buffer_size>{buffer_size}</buffer_size>
<architecture>{arch}</architecture>
<bad_characters>{bad_chars}</bad_characters>
</vulnerability_details>

<current_payload>
{current_payload}
</current_payload>

<instructions>
1. Analyze if the current payload is effective
2. Suggest optimizations for better exploitation
3. Consider bad character avoidance
4. Provide an optimized payload
</instructions>

<output_format>
{{
    "analysis": "brief analysis of current payload",
    "issues": ["list of issues"],
    "optimizations": ["list of suggested optimizations"],
    "optimized_payload_hex": "hex string of optimized payload",
    "confidence": 0.0-1.0,
    "notes": "additional notes"
}}
</output_format>
""",
    use_xml_tags=True
)


# Exploit Strategy Template
EXPLOIT_STRATEGY_TEMPLATE = PromptTemplate(
    template="""<task>
Plan the best exploitation strategy for a given vulnerability.
</task>

<vulnerability>
<type>{vuln_type}</type>
<function>{function}</function>
<address>{address}</address>
<confidence>{confidence}</confidence>
</vulnerability>

<context>
<tainted_args>{tainted_args}</tainted_args>
<sink_api>{sink_api}</sink_api>
<buffer_size>{buffer_size}</buffer_size>
</context>

<instructions>
1. Determine the type of vulnerability and typical exploitation techniques
2. Define the required payload structure
3. Identify potential mitigations to bypass
4. Recommend a testing approach
</instructions>

<output_format>
{{
    "strategy": "brief strategy description",
    "exploitation_type": "stack_overflow|heap_exploit|format_string|etc",
    "payload_structure": {{
        "padding_size": int,
        "control_offset": int,
        "payload_type": "pattern|shellcode|rop"
    }},
    "mitigations_to_consider": ["list"],
    "testing_steps": ["ordered steps"],
    "confidence": 0.0-1.0
}}
</output_format>
""",
    use_xml_tags=True
)


# False Positive Analysis Template
FALSE_POSITIVE_ANALYSIS_TEMPLATE = PromptTemplate(
    template="""<task>
Analyze if a vulnerability finding is likely a false positive.
</task>

<finding>
<type>{vuln_type}</type>
<function>{function}</function>
<address>{address}</address>
<sink_api>{sink_api}</sink_api>
<confidence>{confidence}</confidence>
</finding>

<analysis_context>
<has_bounds_check>{has_bounds_check}</has_bounds_check>
<tainted_args>{tainted_args}</tainted_args>
<path_length>{path_length}</path_length>
<evidence>{evidence}</evidence>
</analysis_context>

<disassembly>
{disasm_context}
</disassembly>

<instructions>
1. Check for common false positive patterns
2. Check for bounds checking presence
3. Check for input validation in path
4. Check API usage context
5. Check for code patterns that suggest safety
</instructions>

<output_format>
{{
    "is_likely_false_positive": true/false,
    "false_positive_probability": 0.0-1.0,
    "reasons": ["list of reasons for assessment"],
    "confidence_adjustment": -0.5 to 0.3,
    "mitigation_detected": ["list of detected mitigations"],
    "recommendation": "verify|reject|needs_more_analysis"
}}
</output_format>
""",
    use_xml_tags=True
)


# Vulnerability Reasoning Template
VULNERABILITY_REASONING_TEMPLATE = PromptTemplate(
    template="""<task>
Provide expert reasoning about a potential vulnerability based on taint analysis.
</task>

<vulnerability>
<type>{vuln_type}</type>
<function>{function}</function>
<sink_api>{sink_api}</sink_api>
</vulnerability>

<taint_results>
{taint_results}
</taint_results>

<instructions>
1. Determine if this vulnerability pattern is exploitable
2. Identify conditions that must be met for exploitation
3. Assess potential impact if exploited
4. Recommend verification steps
</instructions>

<output_format>
{{
    "exploitability_assessment": "likely_exploitable|possibly_exploitable|unlikely_exploitable",
    "required_conditions": ["list of conditions"],
    "potential_impact": "critical|high|medium|low",
    "reasoning": "detailed reasoning",
    "verification_steps": ["ordered steps"],
    "confidence": 0.0-1.0
}}
</output_format>
""",
    use_xml_tags=True
)


# PoC Execution Result Analysis Template
POC_RESULT_ANALYSIS_TEMPLATE = PromptTemplate(
    template="""<task>
Analyze the PoC execution result to determine if the vulnerability was actually triggered.
</task>

<vulnerability>
<type>{vuln_type}</type>
<target_function>{target_function}</target_function>
<expected_behavior>{expected_behavior}</expected_behavior>
</vulnerability>

<execution_result>
<stdout>
{stdout}
</stdout>
<stderr>
{stderr}
</stderr>
<return_code>{return_code}</return_code>
<crashed>{crashed}</crashed>
<crash_info>{crash_info}</crash_info>
</execution_result>

<instructions>
1. Analyze if the vulnerability was actually triggered based on the output
2. Check for indicators of:
   - Successful exploitation (crash at controlled address, memory corruption, etc.)
   - Function rejection (error codes, validation failures, etc.)
   - Incomplete trigger (partial success, edge conditions)
3. Determine if this is a TRUE POSITIVE or FALSE POSITIVE
4. If false positive, explain why
5. If needs improvement, suggest specific fixes

Key indicators:
- Crash at controlled address (0x41414141, etc.) = TRUE POSITIVE
- Function returns error code (0x1XX, negative values) = likely FALSE POSITIVE
- "Access denied", "Invalid parameter" = FALSE POSITIVE (input rejected)
- Timeout without crash = needs more investigation
</instructions>

<output_format>
{{
    "vulnerability_triggered": true/false,
    "verdict": "true_positive|false_positive|needs_improvement|inconclusive",
    "confidence": 0.0-1.0,
    "reasoning": "detailed reasoning for the verdict",
    "indicators": {{
        "positive_indicators": ["list of indicators suggesting real vulnerability"],
        "negative_indicators": ["list of indicators suggesting false positive"]
    }},
    "root_cause": "if false positive, explain the root cause",
    "suggested_improvements": ["list of specific improvements if needed"],
    "should_retry": true/false,
    "retry_strategy": "if should_retry, describe the strategy"
}}
</output_format>
""",
    few_shot_examples=[
        FewShotExample(
            input="Vuln: BUFFER_OVERFLOW, Output: 'Access violation at 0x41414141', crashed: true",
            output=json.dumps({
                "vulnerability_triggered": True,
                "verdict": "true_positive",
                "confidence": 0.95,
                "reasoning": "Crash at controlled address 0x41414141 confirms buffer overflow with EIP control",
                "indicators": {
                    "positive_indicators": ["Crash at controlled pattern address", "Access violation"],
                    "negative_indicators": []
                },
                "root_cause": None,
                "suggested_improvements": [],
                "should_retry": False,
                "retry_strategy": None
            }, indent=2),
            reasoning="Crash at 0x41414141 pattern indicates attacker-controlled EIP"
        ),
        FewShotExample(
            input="Vuln: UNINITIALIZED_MEMORY, Output: 'Function returned: 0x101', crashed: false",
            output=json.dumps({
                "vulnerability_triggered": False,
                "verdict": "false_positive",
                "confidence": 0.85,
                "reasoning": "Function returned error code 0x101 (ERROR_NO_MORE_ITEMS), indicating input was rejected before reaching vulnerable code path",
                "indicators": {
                    "positive_indicators": [],
                    "negative_indicators": ["Error code returned", "No crash", "Function rejected input"]
                },
                "root_cause": "The function validates input before processing and rejected our crafted input",
                "suggested_improvements": ["Investigate valid input format", "Check what conditions allow the function to proceed"],
                "should_retry": True,
                "retry_strategy": "Try with valid input structure to reach the vulnerable code path"
            }, indent=2),
            reasoning="Error code 0x101 indicates the function rejected the input, not a vulnerability"
        )
    ],
    use_xml_tags=True
)


# PoC Fix Suggestion Template
POC_FIX_TEMPLATE = PromptTemplate(
    template="""<task>
Analyze the PoC execution error and provide specific fixes.
</task>

<poc_code>
{poc_code}
</poc_code>

<error_info>
<stderr>
{stderr}
</stderr>
<error_type>{error_type}</error_type>
<traceback>
{traceback}
</traceback>
</error_info>

<instructions>
1. Identify the root cause of the error
2. Provide specific code fixes
3. Explain why the fix will work
4. Consider edge cases
</instructions>

<output_format>
{{
    "error_analysis": "description of what went wrong",
    "root_cause": "specific root cause",
    "fixes": [
        {{
            "location": "line number or code section",
            "original": "original problematic code",
            "fixed": "corrected code",
            "explanation": "why this fix works"
        }}
    ],
    "additional_recommendations": ["list of additional improvements"],
    "confidence": 0.0-1.0
}}
</output_format>
""",
    use_xml_tags=True
)


# Helper Functions
def create_custom_template(
    template_str: str,
    examples: List[Dict[str, str]] = None,
    use_xml: bool = True
) -> PromptTemplate:
    """
    Create custom template
    
    Args:
        template_str: Template string
        examples: Example list [{"input": ..., "output": ..., "reasoning": ...}]
        use_xml: Whether to use XML tags
        
    Returns:
        PromptTemplate instance
    """
    few_shot = []
    if examples:
        for ex in examples:
            few_shot.append(FewShotExample(
                input=ex.get("input", ""),
                output=ex.get("output", ""),
                reasoning=ex.get("reasoning")
            ))
    
    return PromptTemplate(template_str, few_shot, use_xml)
