# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/validation.py
Unified Validation Agent - Integrates static and dynamic verification capabilities.

Phase 5 Implementation:
    - Merged VerifierAgent and ValidatorAgent
    - Established feedback loop mechanism
    - Supports full verification workflow (Static → Dynamic)

Responsibilities:
    - Static Verification (formerly VerifierAgent)
        - Bounds check detection
        - Path reachability analysis
        - Deep vulnerability verification
        - Confidence assessment
        - LLM-driven false positive analysis
    - Dynamic Validation (formerly ValidatorAgent)
        - PoC sandbox execution validation
        - Crash analysis
        - Exploitability assessment
    - Feedback Loop
        - Generate improvement tasks on verification failure
        - Iteratively optimize PoC
"""

from typing import Dict, List, Any, Optional
import logging
import json
import re

from .base import (
    BaseAgent,
    AgentCapability,
    TaskAssignment,
    AgentResult,
)

logger = logging.getLogger(__name__)

# Attempt to import prompt templates
try:
    from .prompt_engineering import (
        FALSE_POSITIVE_ANALYSIS_TEMPLATE,
        VULNERABILITY_REASONING_TEMPLATE,
        POC_RESULT_ANALYSIS_TEMPLATE,
        POC_FIX_TEMPLATE,
    )
    HAVE_PROMPTS = True
except ImportError:
    HAVE_PROMPTS = False
    FALSE_POSITIVE_ANALYSIS_TEMPLATE = ""
    VULNERABILITY_REASONING_TEMPLATE = ""
    POC_RESULT_ANALYSIS_TEMPLATE = None
    POC_FIX_TEMPLATE = None


class ValidationAgent(BaseAgent):
    """
    Unified Validation Agent - Integrates static and dynamic validation.

    Phase 5: Merge VerifierAgent and ValidatorAgent, establish feedback loop.

    Capabilities:
        - VERIFICATION: Static vulnerability verification
        - VALIDATION: Dynamic PoC validation

    Handled Task Types:
        Static Verification (formerly VerifierAgent):
        - deep_verify: Deep binary vulnerability verification
        - check_bounds: Bounds check detection
        - verify_reachability: Path reachability verification
        - cross_verify: Cross-verification across different methods
        - validate_finding: Validate existing findings
        - analyze_pattern_offset: Analysis of pattern offsets (e.g., EIP)
        - check_bad_chars: Detection of bad characters in payloads
        - llm_false_positive_analysis: LLM-driven false positive analysis
        - llm_vulnerability_reasoning: LLM-driven vulnerability reasoning

        Dynamic Validation (formerly ValidatorAgent):
        - validate_poc: Validate PoC code execution
        - sandbox_execute: Execute code in a sandbox
        - analyze_crash: Analyze crash reports
        - assess_exploitability: Assess exploitability based on crashes

        Combined Verification (New):
        - full_verify: Full verification workflow (Static → Dynamic)
    """

    def __init__(self, agent_id: str, *args, **kwargs):
        # Possesses both verification and validation capabilities
        capabilities = kwargs.pop("capabilities", [
            AgentCapability.VERIFICATION,
            AgentCapability.VALIDATION,
        ])

        # Extract agent_registry (BaseAgent does not accept this parameter)
        self.agent_registry = kwargs.pop("agent_registry", None)

        super().__init__(
            agent_id=agent_id,
            capabilities=capabilities,
            *args,
            **kwargs
        )

        # Register all task handlers
        self._task_handlers = {
            # Static Verification
            "deep_verify": self._deep_verify,
            "check_bounds": self._check_bounds,
            "verify_reachability": self._verify_reachability,
            "cross_verify": self._cross_verify,
            "validate_finding": self._validate_finding,
            "analyze_pattern_offset": self._analyze_pattern_offset,
            "check_bad_chars": self._check_bad_chars,
            "llm_false_positive_analysis": self._llm_false_positive_analysis,
            "llm_vulnerability_reasoning": self._llm_vulnerability_reasoning,

            # Dynamic Validation
            "validate_poc": self._validate_poc,
            "sandbox_execute": self._sandbox_execute,
            "analyze_crash": self._analyze_crash,
            "assess_exploitability": self._assess_exploitability,

            # Combined Verification
            "full_verify": self._full_verify,

            # Agent-driven PoC result analysis
            "analyze_poc_result": self._analyze_poc_result,
            "fix_poc_error": self._fix_poc_error,

            # Delegated tasks from AnalyzerAgent
            "verify_dangerous_api": self._verify_dangerous_api,
            "symbolic_verify": self._symbolic_verify,
        }

        self._task_confidence = {
            # Static Verification
            "deep_verify": 0.95,
            "verify_dangerous_api": 0.90,
            "symbolic_verify": 0.85,
            "check_bounds": 0.90,
            "verify_reachability": 0.85,
            "cross_verify": 0.90,
            "validate_finding": 0.88,
            "analyze_pattern_offset": 0.92,
            "check_bad_chars": 0.87,
            "llm_false_positive_analysis": 0.90,
            "llm_vulnerability_reasoning": 0.88,

            # Dynamic Validation
            "validate_poc": 0.95,
            "sandbox_execute": 0.90,
            "analyze_crash": 0.85,
            "assess_exploitability": 0.88,

            # Combined Verification
            "full_verify": 0.95,

            # Agent-driven PoC result analysis
            "analyze_poc_result": 0.92,
            "fix_poc_error": 0.88,
        }

        # Feedback loop configuration
        self._max_poc_improvement_attempts = 3

    @property
    def role(self) -> str:
        return "validator"

    def can_handle(self, task: TaskAssignment) -> float:
        return self._task_confidence.get(task.task_type, 0.0)

    def process_task(self, task: TaskAssignment) -> AgentResult:
        handler = self._task_handlers.get(task.task_type)
        if handler:
            return handler(task)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=False,
            error=f"Unknown task type: {task.task_type}"
        )

    # =========================================================================
    # Combined Verification (New)
    # =========================================================================

    def _full_verify(self, task: TaskAssignment) -> AgentResult:
        """
        Full verification workflow: Static → Dynamic

        Phase 5: Combine static and dynamic verification, establish feedback loop.
        """
        finding_id = task.parameters.get("finding_id")
        address = task.parameters.get("address")
        vuln_type = task.parameters.get("vuln_type")

        if not finding_id and not address:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing finding_id or address parameter"
            )

        # Get finding information
        finding = None
        if finding_id:
            finding = self.shared_state.get_finding(finding_id)
            if finding:
                address = address or finding.address
                vuln_type = vuln_type or finding.vuln_type

        logger.info(f"Full verification: finding={finding_id}, address={address}, type={vuln_type}")

        # Step 1: Static verification
        static_task = TaskAssignment.create(
            task_type="deep_verify",
            parameters={
                "finding_id": finding_id,
                "address": address,
                "vuln_type": vuln_type,
            }
        )
        static_result = self._deep_verify(static_task)

        if not static_result.success:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Static verification failed: {static_result.error}",
                metadata={"stage": "static_verify"}
            )

        # Check static verification results
        is_exploitable = static_result.metadata.get("is_exploitable", False)
        confidence = static_result.metadata.get("confidence_score", 0)

        if not is_exploitable and confidence < 0.5:
            # Static verification failed
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                findings=static_result.findings,
                metadata={
                    "stage": "static_verify",
                    "verified": False,
                    "reason": "Low confidence in static analysis",
                    "confidence": confidence,
                }
            )

        # Step 2: If PoC is available, perform dynamic validation
        if finding and finding.poc_code:
            poc_task = TaskAssignment.create(
                task_type="validate_poc",
                parameters={
                    "finding_id": finding_id,
                    "poc_code": finding.poc_code,
                }
            )
            dynamic_result = self._validate_poc(poc_task)

            # Process dynamic validation results
            poc_validated = dynamic_result.metadata.get("exploit_successful", False)

            if not poc_validated:
                # Feedback loop: Generate PoC improvement task
                attempt = task.parameters.get("attempt", 0)
                next_tasks = []

                if attempt < self._max_poc_improvement_attempts:
                    next_tasks.append(TaskAssignment.create(
                        task_type="improve_poc",
                        parameters={
                            "finding_id": finding_id,
                            "failure_reason": dynamic_result.artifacts.get("validation_result", {}).get("crash_info", {}),
                            "previous_poc": finding.poc_code,
                            "attempt": attempt + 1,
                        },
                        priority=8,
                    ))
                    logger.info(f"Feedback loop: requesting PoC improvement (attempt {attempt + 1})")

                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    next_tasks=next_tasks,
                    metadata={
                        "stage": "dynamic_verify",
                        "poc_validated": False,
                        "attempt": attempt,
                        "feedback_generated": len(next_tasks) > 0,
                    }
                )

            # Dynamic validation successful
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                findings=static_result.findings,
                artifacts={
                    "static_result": static_result.artifacts,
                    "dynamic_result": dynamic_result.artifacts,
                },
                metadata={
                    "stage": "complete",
                    "static_verified": True,
                    "poc_validated": True,
                    "confidence": confidence,
                }
            )

        # No PoC, only return static verification results
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            findings=static_result.findings,
            next_tasks=static_result.next_tasks,
            metadata={
                "stage": "static_only",
                "verified": is_exploitable,
                "confidence": confidence,
                "has_poc": False,
            }
        )

    # =========================================================================
    # Static Verification (formerly VerifierAgent)
    # =========================================================================

    def _deep_verify(self, task: TaskAssignment) -> AgentResult:
        """Deeply verify vulnerability"""
        address = task.parameters.get("address")
        vuln_type = task.parameters.get("vuln_type", "buffer_overflow")
        tainted_arg = task.parameters.get("tainted_arg_index", 0)

        if not address:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing address parameter"
            )

        result = self.call_tool("deep_verify_vulnerability", {
            "sink_address": address,
            "vuln_type": vuln_type,
            "tainted_arg_index": tainted_arg
        })

        findings = []
        next_tasks = []

        if result and result.status.value == "success" and result.data:
            data = result.data
            confidence = data.get("confidence_score", 0)

            if data.get("is_likely_exploitable"):
                finding = {
                    "vuln_type": vuln_type,
                    "severity": "High" if confidence >= 0.7 else "Medium",
                    "confidence": confidence,
                    "address": address,
                    "evidence": data.get("evidence", []),
                    "status": "verified",
                }
                findings.append(finding)

                finding_id = task.parameters.get("finding_id")
                if finding_id:
                    self.shared_state.update_finding(
                        finding_id,
                        status="verified",
                        verified_by=self.agent_id,
                        confidence=confidence
                    )

                if confidence >= 0.6:
                    next_tasks.append(TaskAssignment.create(
                        task_type="generate_poc",
                        parameters={
                            "address": address,
                            "vuln_type": vuln_type,
                            "confidence": confidence,
                            "finding_id": finding_id,
                        },
                        priority=6
                    ))

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                findings=findings,
                next_tasks=next_tasks,
                artifacts={"verification_result": data},
                metadata={
                    "confidence_score": confidence,
                    "is_exploitable": data.get("is_likely_exploitable", False),
                }
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=False,
            error=result.error if result else "Tool call failed"
        )

    def _check_bounds(self, task: TaskAssignment) -> AgentResult:
        """Check for bounds checking"""
        address = task.parameters.get("address")
        register = task.parameters.get("register", "rcx")

        if not address:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing address parameter"
            )

        result = self.call_tool("check_bounds_before_sink", {
            "sink_address": address,
            "tainted_register": register
        })

        artifacts = {}
        has_bounds_check = False

        if result and result.status.value == "success" and result.data:
            artifacts["bounds_check"] = result.data
            has_bounds_check = result.data.get("has_bounds_check", False)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts=artifacts,
            metadata={
                "has_bounds_check": has_bounds_check,
                "likely_false_positive": has_bounds_check,
            }
        )

    def _verify_reachability(self, task: TaskAssignment) -> AgentResult:
        """Verify path reachability"""
        export_name = task.parameters.get("export_name")
        sink_name = task.parameters.get("sink_name")

        if not export_name or not sink_name:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing export_name or sink_name parameter"
            )

        result = self.call_tool("find_path_to_sink", {
            "export_name": export_name,
            "sink_name": sink_name
        })

        is_reachable = False
        path_info = None

        if result and result.status.value == "success" and result.data:
            is_reachable = result.data.get("path_found", False)
            path_info = result.data.get("path", [])

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"path_info": path_info},
            metadata={
                "is_reachable": is_reachable,
                "path_length": len(path_info) if path_info else 0,
            }
        )

    def _cross_verify(self, task: TaskAssignment) -> AgentResult:
        """Cross-verify findings"""
        finding_id = task.parameters.get("finding_id")
        address = task.parameters.get("address")

        if not address:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing address parameter"
            )

        verification_results = {}

        bounds_result = self.call_tool("check_bounds_before_sink", {
            "sink_address": address,
            "tainted_register": "rcx"
        })
        if bounds_result and bounds_result.data:
            verification_results["bounds_check"] = bounds_result.data

        disasm_result = self.call_tool("disassemble_function", {
            "address": address,
            "max_instructions": 30
        })
        if disasm_result and disasm_result.data:
            verification_results["disassembly"] = {
                "instruction_count": disasm_result.data.get("instruction_count", 0),
                "is_import": disasm_result.data.get("is_import", False),
            }

        confidence = 0.5
        if verification_results.get("bounds_check", {}).get("has_bounds_check"):
            confidence -= 0.2
        if verification_results.get("disassembly", {}).get("is_import"):
            confidence += 0.1

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"verification_results": verification_results},
            metadata={
                "cross_verified": True,
                "adjusted_confidence": confidence,
            }
        )

    def _validate_finding(self, task: TaskAssignment) -> AgentResult:
        """Validate existing findings"""
        finding_id = task.parameters.get("finding_id")
        address = task.parameters.get("address")
        vuln_type = task.parameters.get("vuln_type")
        source = task.parameters.get("source")
        original_confidence = task.parameters.get("original_confidence", 0.5)

        # Phase 3: Get current version for optimistic locking
        state_version = self.shared_state.get_version()

        if finding_id:
            finding = self.shared_state.get_finding(finding_id)
            if not finding:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error=f"Finding not found: {finding_id}"
                )
            address = finding.address
            vuln_type = finding.vuln_type
        elif not address:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing finding_id or address parameter"
            )

        result = self.call_tool("deep_verify_vulnerability", {
            "sink_address": address,
            "vuln_type": vuln_type,
        })

        if result and result.status.value == "success" and result.data:
            new_confidence = result.data.get("confidence_score", original_confidence)
            is_valid = result.data.get("is_likely_exploitable", False)
            new_status = "verified" if is_valid else "rejected"

            if finding_id:
                # Phase 3: Update using optimistic locking
                update_success, _ = self.shared_state.compare_and_update_finding(
                    expected_version=state_version,
                    finding_id=finding_id,
                    updates={
                        "status": new_status,
                        "verified_by": self.agent_id,
                        "confidence": new_confidence,
                    }
                )
                if not update_success:
                    logger.warning(f"Optimistic lock failed for {finding_id}, falling back to regular update")
                    self.shared_state.update_finding(
                        finding_id,
                        status=new_status,
                        verified_by=self.agent_id,
                        confidence=new_confidence
                    )
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=True,
                    metadata={
                        "finding_id": finding_id,
                        "new_status": new_status,
                        "new_confidence": new_confidence,
                    }
                )

            import uuid
            findings = []
            next_tasks = []
            if is_valid or new_confidence >= 0.5:
                adjusted_confidence = min(0.95, new_confidence + 0.15) if source == "algorithm" else new_confidence
                generated_finding_id = f"finding-{uuid.uuid4().hex[:8]}"

                finding_data = {
                    "finding_id": generated_finding_id,
                    "vuln_type": vuln_type,
                    "severity": "High" if is_valid else "Medium",
                    "confidence": adjusted_confidence,
                    "address": address,
                    "function": task.parameters.get("function"),
                    "evidence": [f"Algorithm found, AI verified (original: {original_confidence:.2f})"],
                    "cross_validated": True,
                    "status": "verified",
                    "verified_by": [self.agent_id],
                    "poc_path": task.parameters.get("poc_path"),
                    "harness_path": task.parameters.get("harness_path"),
                }
                findings.append(finding_data)

                if adjusted_confidence >= 0.6:
                    func_name = task.parameters.get("function") or f"func_{hex(address) if isinstance(address, int) else address}"
                    next_tasks.append(TaskAssignment.create(
                        task_type="generate_poc",
                        parameters={
                            "finding_id": generated_finding_id,
                            "address": address,
                            "vuln_type": vuln_type,
                            "function": func_name,
                        },
                        priority=8
                    ))

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                findings=findings,
                next_tasks=next_tasks,
                metadata={
                    "source": source,
                    "original_confidence": original_confidence,
                    "new_confidence": new_confidence,
                    "is_valid": is_valid,
                    "cross_validated": bool(findings),
                }
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=False,
            error="Validation tool call failed"
        )

    def _analyze_pattern_offset(self, task: TaskAssignment) -> AgentResult:
        """Analyze pattern offset"""
        eip_value = task.parameters.get("eip_value")
        crash_data = task.parameters.get("crash_data")
        finding_id = task.parameters.get("finding_id")

        if not eip_value:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="EIP value required for pattern offset analysis"
            )

        try:
            from luodllhack.exploit.payload import PatternGenerator
            offset = PatternGenerator.offset(int(eip_value) if isinstance(eip_value, str) else eip_value)

            finding = None
            if offset is not None:
                finding = {
                    "vuln_type": "PATTERN_OFFSET_ANALYSIS",
                    "severity": "Info",
                    "confidence": 0.95,
                    "address": eip_value,
                    "function": "offset_calculation",
                    "sink_api": "pattern_analysis",
                    "evidence": [f"Calculated offset: {offset}"],
                }

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                findings=[finding] if finding else [],
                artifacts={
                    "calculated_offset": offset,
                    "eip_value": eip_value,
                    "crash_data": crash_data,
                    "finding_id": finding_id,
                },
                metadata={"offset": offset, "eip_value": eip_value}
            )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Pattern offset analysis failed: {str(e)}"
            )

    def _check_bad_chars(self, task: TaskAssignment) -> AgentResult:
        """Check for bad characters"""
        target_address = task.parameters.get("target_address")
        target_function = task.parameters.get("target_function")

        try:
            from luodllhack.exploit.payload import BadCharFinder
            import speakeasy
        except ImportError:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Required modules not available for bad character check"
            )

        if not target_address:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Target address required for bad character check"
            )

        try:
            finder = BadCharFinder()
            result = finder.detect(
                target_address,
                str(self.engine.binary_path) if hasattr(self, 'engine') else "",
                range(256),
                speakeasy_timeout=task.parameters.get("timeout", 60)
            )

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=result.success,
                findings=[{
                    "vuln_type": "BAD_CHARACTER_VERIFICATION",
                    "severity": "Info",
                    "confidence": 0.85 if result.success else 0.3,
                    "address": target_address,
                    "function": target_function or "unknown",
                }] if result.success else [],
                artifacts={
                    "detected_bad_chars": result.detected_bad_chars,
                    "safe_chars": result.safe_chars,
                    "total_tested": result.total_tested,
                },
                metadata={
                    "bad_chars_count": len(result.detected_bad_chars),
                    "safe_chars_count": len(result.safe_chars),
                }
            )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Bad character check failed: {str(e)}"
            )

    def _llm_false_positive_analysis(self, task: TaskAssignment) -> AgentResult:
        """LLM-driven false positive analysis"""
        finding_id = task.parameters.get("finding_id")
        finding_data = task.parameters.get("finding", {})

        if finding_id and not finding_data:
            finding = self.shared_state.get_finding(finding_id)
            if finding:
                finding_data = {
                    "vuln_type": finding.vuln_type,
                    "function": finding.function,
                    "address": finding.address,
                    "sink_api": getattr(finding, 'sink_api', 'unknown'),
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
                }

        if not finding_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing finding data"
            )

        has_bounds_check = task.parameters.get("has_bounds_check", False)

        if not has_bounds_check and finding_data.get("address"):
            bounds_result = self.call_tool("check_bounds_before_sink", {
                "sink_address": finding_data["address"],
                "tainted_register": "rcx"
            })
            if bounds_result and bounds_result.data:
                has_bounds_check = bounds_result.data.get("has_bounds_check", False)

        if self.llm_pool is None or not HAVE_PROMPTS:
            fp_probability = 0.3 if has_bounds_check else 0.1
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                artifacts={
                    "fp_analysis": {
                        "is_likely_false_positive": has_bounds_check,
                        "false_positive_probability": fp_probability,
                        "reasons": ["bounds check detected"] if has_bounds_check else [],
                        "recommendation": "reject" if has_bounds_check else "verify"
                    }
                },
                metadata={"llm_analyzed": False}
            )

        prompt = FALSE_POSITIVE_ANALYSIS_TEMPLATE.format(
            vuln_type=finding_data.get("vuln_type", "unknown"),
            function=finding_data.get("function", "unknown"),
            address=finding_data.get("address", "unknown"),
            sink_api=finding_data.get("sink_api", "unknown"),
            confidence=finding_data.get("confidence", 0.5),
            has_bounds_check=has_bounds_check,
            tainted_args=task.parameters.get("tainted_args", []),
            path_length=task.parameters.get("path_length", 0),
            evidence=finding_data.get("evidence", []),
            disasm_context=task.parameters.get("disasm_context", "Not available")[:1000],
        )

        try:
            response = self.call_llm(prompt)
            if response is None or response.text is None:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error="LLM returned empty response"
                )

            fp_analysis = self._parse_json_response(response.text)
            if fp_analysis is None:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error="Failed to parse LLM response"
                )

            is_fp = fp_analysis.get("is_likely_false_positive", False)
            new_confidence = max(0.0, min(1.0,
                finding_data.get("confidence", 0.5) + fp_analysis.get("confidence_adjustment", 0)))

            if finding_id:
                new_status = "rejected" if is_fp and fp_analysis.get("false_positive_probability", 0) > 0.7 else "detected"
                self.shared_state.update_finding(
                    finding_id,
                    fp_analyzed=True,
                    fp_probability=fp_analysis.get("false_positive_probability", 0),
                    confidence=new_confidence,
                    status=new_status
                )

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                artifacts={"fp_analysis": fp_analysis},
                metadata={
                    "llm_analyzed": True,
                    "is_likely_false_positive": is_fp,
                    "fp_probability": fp_analysis.get("false_positive_probability", 0),
                }
            )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"FP analysis failed: {str(e)}"
            )

    def _llm_vulnerability_reasoning(self, task: TaskAssignment) -> AgentResult:
        """LLM-driven vulnerability reasoning"""
        vuln_type = task.parameters.get("vuln_type", "unknown")
        function = task.parameters.get("function", "unknown")
        sink_api = task.parameters.get("sink_api", "unknown")
        taint_results = task.parameters.get("taint_results", "Not available")

        if self.llm_pool is None or not HAVE_PROMPTS:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="No LLM available for vulnerability reasoning"
            )

        prompt = VULNERABILITY_REASONING_TEMPLATE.format(
            vuln_type=vuln_type,
            function=function,
            sink_api=sink_api,
            taint_results=str(taint_results)[:2000],
        )

        try:
            response = self.call_llm(prompt)
            if response is None or response.text is None:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error="LLM returned empty response"
                )

            reasoning = self._parse_json_response(response.text)
            if reasoning is None:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error="Failed to parse LLM reasoning response"
                )

            next_tasks = []
            if reasoning.get("exploitability_assessment") == "likely_exploitable":
                next_tasks.append(TaskAssignment.create(
                    task_type="generate_poc",
                    parameters={
                        "vuln_type": vuln_type,
                        "function": function,
                        "llm_reasoning": reasoning,
                    },
                    priority=8
                ))

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                artifacts={"vulnerability_reasoning": reasoning},
                next_tasks=next_tasks,
                metadata={
                    "llm_reasoned": True,
                    "exploitability": reasoning.get("exploitability_assessment"),
                    "confidence": reasoning.get("confidence", 0.5),
                }
            )
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Vulnerability reasoning failed: {str(e)}"
            )

    # =========================================================================
    # Dynamic Validation (formerly ValidatorAgent)
    # =========================================================================

    def _validate_poc(self, task: TaskAssignment) -> AgentResult:
        """
        Validate PoC code - Agent-driven complete validation workflow

        Workflow:
        1. Execute PoC
        2. If Python execution error → Generate fix_poc_error task for Agent to fix
        3. If execution successful → Generate analyze_poc_result task for Agent to analyze output
        4. Agent analysis result determines if it's a true vulnerability or false positive
        """
        poc_code = task.parameters.get("poc_code")
        finding_id = task.parameters.get("finding_id")
        vuln_type = task.parameters.get("vuln_type", "UNKNOWN")
        target_function = task.parameters.get("target_function", "unknown")
        attempt = task.parameters.get("attempt", 0)

        if not poc_code:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing poc_code parameter"
            )

        result = self.call_tool("verify_poc", {"poc_code": poc_code})

        validation_result = {
            "poc_validated": False,
            "crash_detected": False,
            "exploit_successful": False,
            "needs_agent_analysis": False,
        }
        next_tasks = []

        if result and result.status.value == "success" and result.data:
            data = result.data
            crashed = data.get("crashed", False)
            timeout = data.get("timeout", False)
            return_code = data.get("return_code")
            stderr = data.get("stderr", "") or ""
            stdout = data.get("stdout", "") or ""

            # Detect Python execution errors (not target function errors)
            python_error_patterns = [
                "traceback (most recent call last)",
                "syntaxerror:",
                "nameerror:",
                "typeerror:",
                "attributeerror:",
                "importerror:",
                "modulenotfounderror:",
                "argumenterror:",
                "overflowerror:",
            ]
            has_python_error = any(
                pattern in stderr.lower() for pattern in python_error_patterns
            )

            validation_result = {
                "poc_validated": False,  # Determined after Agent analysis
                "crash_detected": crashed,
                "exploit_successful": False,
                "crash_info": {
                    "crash_type": data.get("crash_type"),
                    "return_code": return_code,
                    "stderr": stderr,
                },
                "execution_log": stdout,
                "execution_time": data.get("execution_time"),
                "timeout": timeout,
                "needs_agent_analysis": True,
            }

            if has_python_error:
                if attempt < self._max_poc_improvement_attempts:
                    # Case 1a: PoC itself has a Python error, attempt fix
                    logger.info(f"PoC has Python execution error, requesting fix (attempt {attempt + 1})")
                    next_tasks.append(TaskAssignment.create(
                        task_type="fix_poc_error",
                        parameters={
                            "finding_id": finding_id,
                            "poc_code": poc_code,
                            "stderr": stderr,
                            "error_type": self._extract_python_error_type(stderr),
                            "attempt": attempt + 1,
                            "vuln_type": vuln_type,
                            "target_function": target_function,
                        },
                        priority=9,
                    ))
                    validation_result["status"] = "poc_error_needs_fix"
                else:
                    # Case 1b: Max retries reached, remove invalid PoC
                    logger.info(f"PoC fix attempts exhausted, removing invalid PoC")
                    validation_result["status"] = "poc_unfixable"
                    if finding_id:
                        self.shared_state.update_finding(
                            finding_id,
                            poc_code=None,  # Remove invalid PoC - non-functional PoC cannot serve as evidence
                            status="poc_unfixable",
                        )

            elif timeout:
                # Case 2: Timeout
                logger.info("PoC execution timeout")
                validation_result["status"] = "timeout"
                if attempt < self._max_poc_improvement_attempts:
                    next_tasks.append(TaskAssignment.create(
                        task_type="improve_poc",
                        parameters={
                            "finding_id": finding_id,
                            "previous_poc": poc_code,
                            "failure_reason": "Execution timeout",
                            "attempt": attempt + 1,
                        },
                        priority=8,
                    ))
                else:
                    # Max retries reached, remove invalid PoC
                    logger.info(f"PoC timeout attempts exhausted, removing PoC")
                    if finding_id:
                        self.shared_state.update_finding(
                            finding_id,
                            poc_code=None,  # Remove timed-out PoC
                            status="poc_timeout",
                        )

            else:
                # Case 3: PoC execution complete (no Python error), request Agent analysis
                logger.info("PoC executed successfully, requesting Agent analysis")
                next_tasks.append(TaskAssignment.create(
                    task_type="analyze_poc_result",
                    parameters={
                        "finding_id": finding_id,
                        "vuln_type": vuln_type,
                        "target_function": target_function,
                        "stdout": stdout,
                        "stderr": stderr,
                        "return_code": return_code,
                        "crashed": crashed,
                        "crash_info": data.get("crash_type"),
                        "poc_code": poc_code,
                        "poc_path": data.get("poc_path"),  # Path to PoC file
                        "attempt": attempt,
                    },
                    priority=9,
                ))
                validation_result["status"] = "pending_agent_analysis"

            # Update finding status
            if finding_id:
                self.shared_state.update_finding(
                    finding_id,
                    status="validating",
                    validated_by=self.agent_id,
                    validation_result=validation_result
                )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,  # Execution successful; analysis results determined by subsequent tasks
            next_tasks=next_tasks,
            artifacts={"validation_result": validation_result},
            metadata={
                "crash_detected": validation_result.get("crash_detected", False),
                "needs_agent_analysis": validation_result.get("needs_agent_analysis", False),
            }
        )

    def _extract_python_error_type(self, stderr: str) -> str:
        """Extract Python error type from stderr"""
        error_types = [
            "SyntaxError", "NameError", "TypeError", "AttributeError",
            "ImportError", "ModuleNotFoundError", "ArgumentError",
            "OverflowError", "ValueError", "KeyError", "IndexError",
            "FileNotFoundError", "OSError", "RuntimeError",
        ]
        stderr_lower = stderr.lower()
        for et in error_types:
            if et.lower() in stderr_lower:
                return et
        return "UnknownError"

    def _sandbox_execute(self, task: TaskAssignment) -> AgentResult:
        """Sandbox execution"""
        code = task.parameters.get("code")
        timeout = task.parameters.get("timeout", 30)

        if not code:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing code parameter"
            )

        result = self.call_tool("sandbox_execute", {
            "code": code,
            "timeout": timeout
        })

        execution_result = {}
        if result and result.status.value == "success" and result.data:
            execution_result = {
                "exit_code": result.data.get("exit_code"),
                "stdout": result.data.get("stdout"),
                "stderr": result.data.get("stderr"),
                "crashed": result.data.get("crashed", False),
                "timeout_reached": result.data.get("timeout_reached", False),
            }

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=result is not None and result.status.value == "success",
            artifacts={"execution_result": execution_result},
        )

    def _analyze_crash(self, task: TaskAssignment) -> AgentResult:
        """Crash analysis"""
        crash_info = task.parameters.get("crash_info", {})
        finding_id = task.parameters.get("finding_id")

        if not crash_info:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing crash_info parameter"
            )

        analysis = {
            "crash_type": "unknown",
            "severity": "Medium",
            "exploitable": False,
            "details": {},
        }

        exception_code = crash_info.get("exception_code", 0)
        fault_address = crash_info.get("fault_address")

        if exception_code == 0xC0000005:  # ACCESS_VIOLATION
            analysis["crash_type"] = "access_violation"
            access_type = crash_info.get("access_type", "read")
            if access_type == "write":
                analysis["severity"] = "Critical"
                analysis["exploitable"] = True
            else:
                analysis["severity"] = "High"
                analysis["exploitable"] = fault_address == 0x41414141
        elif exception_code == 0xC0000409:  # STATUS_STACK_BUFFER_OVERRUN
            analysis["crash_type"] = "stack_buffer_overrun"
            analysis["severity"] = "Critical"
            analysis["exploitable"] = True
        elif exception_code == 0xC000001D:  # ILLEGAL_INSTRUCTION
            analysis["crash_type"] = "illegal_instruction"
            analysis["severity"] = "High"
            analysis["exploitable"] = True

        analysis["details"] = {
            "exception_code": hex(exception_code) if exception_code else None,
            "fault_address": hex(fault_address) if fault_address else None,
            "registers": crash_info.get("registers", {}),
        }

        # LLM Enhanced Analysis
        if self.llm_pool is not None:
            try:
                llm_result = self._llm_analyze_crash(crash_info, analysis)
                if llm_result:
                    if llm_result.get("severity"):
                        analysis["severity"] = llm_result["severity"]
                    if llm_result.get("exploitable") is not None:
                        analysis["exploitable"] = llm_result["exploitable"]
                    if llm_result.get("root_cause"):
                        analysis["details"]["root_cause"] = llm_result["root_cause"]
                    analysis["llm_analysis"] = llm_result
            except Exception as e:
                logger.warning(f"LLM crash analysis failed: {e}")

        if finding_id and analysis["exploitable"]:
            self.shared_state.update_finding(
                finding_id,
                crash_analysis=analysis,
                severity=analysis["severity"]
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"crash_analysis": analysis},
            metadata={
                "crash_type": analysis["crash_type"],
                "exploitable": analysis["exploitable"],
                "severity": analysis["severity"],
            }
        )

    def _assess_exploitability(self, task: TaskAssignment) -> AgentResult:
        """Assess exploitability"""
        finding_id = task.parameters.get("finding_id")
        vuln_type = task.parameters.get("vuln_type", "buffer_overflow")
        crash_info = task.parameters.get("crash_info")
        has_poc = task.parameters.get("has_poc", False)

        assessment = {
            "exploitability": "Unknown",
            "confidence": 0.0,
            "factors": [],
            "mitigations": [],
        }

        score = 0.5

        if has_poc:
            score += 0.2
            assessment["factors"].append("Working PoC exists")

        if crash_info:
            if crash_info.get("eip_controlled") or crash_info.get("rip_controlled"):
                score += 0.3
                assessment["factors"].append("Control flow hijacked")
            if crash_info.get("write_primitive"):
                score += 0.2
                assessment["factors"].append("Arbitrary write primitive")

        vuln_scores = {
            "buffer_overflow": 0.1,
            "heap_overflow": 0.15,
            "use_after_free": 0.2,
            "format_string": 0.1,
            "command_injection": 0.3,
            "path_traversal": 0.05,
        }
        score += vuln_scores.get(vuln_type, 0)

        mitigations = task.parameters.get("mitigations", {})
        if mitigations.get("aslr"):
            score -= 0.1
            assessment["mitigations"].append("ASLR enabled")
        if mitigations.get("dep"):
            score -= 0.1
            assessment["mitigations"].append("DEP/NX enabled")
        if mitigations.get("cfg"):
            score -= 0.15
            assessment["mitigations"].append("CFG enabled")
        if mitigations.get("stack_canary"):
            score -= 0.1
            assessment["mitigations"].append("Stack canary present")

        score = max(0.0, min(1.0, score))
        assessment["confidence"] = score

        if score >= 0.8:
            assessment["exploitability"] = "High"
        elif score >= 0.5:
            assessment["exploitability"] = "Medium"
        elif score >= 0.3:
            assessment["exploitability"] = "Low"
        else:
            assessment["exploitability"] = "Unlikely"

        if finding_id:
            self.shared_state.update_finding(
                finding_id,
                exploitability=assessment["exploitability"],
                exploitability_confidence=score
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"assessment": assessment},
            metadata={
                "exploitability": assessment["exploitability"],
                "confidence": score,
            }
        )

    # =========================================================================
    # Agent-driven PoC Result Analysis
    # =========================================================================

    def _analyze_poc_result(self, task: TaskAssignment) -> AgentResult:
        """
        Agent-driven PoC execution result analysis

        Uses LLM to analyze PoC execution output and determine:
        - If the vulnerability was actually triggered
        - If it's a true positive or false positive
        - If the PoC needs improvement
        """
        finding_id = task.parameters.get("finding_id")
        vuln_type = task.parameters.get("vuln_type", "UNKNOWN")
        target_function = task.parameters.get("target_function", "unknown")
        stdout = task.parameters.get("stdout", "")
        stderr = task.parameters.get("stderr", "")
        return_code = task.parameters.get("return_code")
        crashed = task.parameters.get("crashed", False)
        crash_info = task.parameters.get("crash_info")
        poc_code = task.parameters.get("poc_code", "")
        poc_path = task.parameters.get("poc_path")  # Path to PoC file
        attempt = task.parameters.get("attempt", 0)

        # Construct description of expected behaviors
        expected_behaviors = {
            "BUFFER_OVERFLOW": "Crash at controlled address (0x41414141), access violation, stack corruption",
            "HEAP_OVERFLOW": "Heap corruption, crash in heap operations, controlled heap metadata",
            "USE_AFTER_FREE": "Crash accessing freed memory, use of dangling pointer",
            "FORMAT_STRING": "Crash or memory leak via format specifiers, unexpected output",
            "CONTROL_FLOW_HIJACK": "EIP/RIP control, jump to controlled address",
            "UNINITIALIZED_MEMORY": "Use of uninitialized data, information leak",
            "UNTRUSTED_POINTER_DEREFERENCE": "Crash when dereferencing attacker-controlled pointer value",
            "COMMAND_INJECTION": "Command execution, unexpected process spawning",
            "PATH_TRAVERSAL": "Access to files outside intended directory",
            "INTEGER_OVERFLOW": "Arithmetic overflow leading to unexpected behavior",
        }
        expected_behavior = expected_behaviors.get(vuln_type, "Unexpected behavior indicating vulnerability")

        analysis_result = {
            "vulnerability_triggered": False,
            "verdict": "inconclusive",
            "confidence": 0.0,
            "reasoning": "",
            "is_false_positive": False,
        }
        next_tasks = []

        # Use LLM for analysis
        if self.llm_pool is not None and HAVE_PROMPTS and POC_RESULT_ANALYSIS_TEMPLATE:
            try:
                prompt = POC_RESULT_ANALYSIS_TEMPLATE.format(
                    vuln_type=vuln_type,
                    target_function=target_function,
                    expected_behavior=expected_behavior,
                    stdout=stdout[:3000] if stdout else "(empty)",  # Limit length
                    stderr=stderr[:1000] if stderr else "(empty)",
                    return_code=return_code,
                    crashed=crashed,
                    crash_info=crash_info or "(no crash)",
                )

                response = self.call_llm(prompt)
                if response and response.text:
                    llm_result = self._parse_json_response(response.text)
                    if llm_result:
                        analysis_result = {
                            "vulnerability_triggered": llm_result.get("vulnerability_triggered", False),
                            "verdict": llm_result.get("verdict", "inconclusive"),
                            "confidence": llm_result.get("confidence", 0.0),
                            "reasoning": llm_result.get("reasoning", ""),
                            "is_false_positive": llm_result.get("verdict") == "false_positive",
                            "indicators": llm_result.get("indicators", {}),
                            "root_cause": llm_result.get("root_cause"),
                            "suggested_improvements": llm_result.get("suggested_improvements", []),
                            "should_retry": llm_result.get("should_retry", False),
                            "retry_strategy": llm_result.get("retry_strategy"),
                        }

                        logger.info(f"LLM PoC analysis verdict: {analysis_result['verdict']} "
                                  f"(confidence: {analysis_result['confidence']:.2f})")

            except Exception as e:
                logger.warning(f"LLM PoC result analysis failed: {e}")
                # Fallback to rule-based analysis
                analysis_result = self._rule_based_poc_analysis(
                    stdout, stderr, return_code, crashed, vuln_type
                )

        else:
            # No LLM available, use rule-based analysis
            analysis_result = self._rule_based_poc_analysis(
                stdout, stderr, return_code, crashed, vuln_type
            )

        # =====================================================================
        # Calculate Agent-driven confidence adjustment (Agent takes precedence)
        # =====================================================================
        confidence_adjustment = self._calculate_agent_confidence_adjustment(
            verdict=analysis_result["verdict"],
            crashed=crashed,
            stdout=stdout,
            analysis_confidence=analysis_result.get("confidence", 0.5),
        )
        analysis_result["confidence_adjustment"] = confidence_adjustment

        # Update finding status and generate subsequent tasks based on analysis results
        if finding_id:
            # Get current finding confidence
            finding = self.shared_state.get_finding(finding_id)
            current_confidence = finding.confidence if finding else 0.5

            # Calculate new confidence (Agent adjustment + original confidence)
            new_confidence = max(0.0, min(1.0, current_confidence + confidence_adjustment))

            if analysis_result["verdict"] == "true_positive":
                # True positive - substantially increase confidence, preserve PoC as evidence
                new_confidence = max(new_confidence, 0.85)  # At least 85%
                self.shared_state.update_finding(
                    finding_id,
                    status="validated",
                    validated_by=self.agent_id,
                    validation_result=analysis_result,
                    is_false_positive=False,
                    confidence=new_confidence,
                    poc_path=poc_path,  # Save valid PoC file path as evidence
                )
                logger.info(f"Finding {finding_id} validated as TRUE POSITIVE (confidence: {new_confidence:.2f}, poc: {poc_path})")

            elif analysis_result["verdict"] == "false_positive":
                # False positive - remove PoC (invalid evidence)
                new_confidence = min(new_confidence, 0.15)
                self.shared_state.update_finding(
                    finding_id,
                    status="false_positive",
                    validated_by=self.agent_id,
                    validation_result=analysis_result,
                    is_false_positive=True,
                    false_positive_reason=analysis_result.get("reasoning", ""),
                    confidence=new_confidence,
                    poc_code=None,  # Delete PoC code
                    poc_path=None,  # Clear PoC path - false positive PoC cannot serve as evidence
                )
                logger.info(f"Finding {finding_id} marked as FALSE POSITIVE, PoC removed")

            elif analysis_result["verdict"] == "needs_improvement":
                # Needs PoC improvement - maintain original confidence, wait for further validation
                if attempt < self._max_poc_improvement_attempts:
                    next_tasks.append(TaskAssignment.create(
                        task_type="improve_poc",
                        parameters={
                            "finding_id": finding_id,
                            "previous_poc": poc_code,
                            "failure_reason": analysis_result.get("reasoning", ""),
                            "suggested_improvements": analysis_result.get("suggested_improvements", []),
                            "attempt": attempt + 1,
                        },
                        priority=8,
                    ))
                    logger.info(f"PoC needs improvement, requesting retry (attempt {attempt + 1})")
                else:
                    # Max retries reached, remove invalid PoC
                    self.shared_state.update_finding(
                        finding_id,
                        poc_code=None,  # Remove unfixable PoC
                    )
                    logger.info(f"PoC improvement attempts exhausted, PoC removed")

                self.shared_state.update_finding(
                    finding_id,
                    status="poc_needs_improvement",
                    validated_by=self.agent_id,
                    validation_result=analysis_result
                )

            else:
                # Uncertain - remove PoC (unreliable evidence)
                new_confidence = current_confidence * 0.9
                self.shared_state.update_finding(
                    finding_id,
                    status="inconclusive",
                    validated_by=self.agent_id,
                    validation_result=analysis_result,
                    confidence=new_confidence,
                    poc_code=None,  # Delete PoC code
                    poc_path=None,  # Clear PoC path - inconclusive PoC cannot serve as evidence
                )
                logger.info(f"Finding {finding_id} inconclusive, PoC removed")

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            next_tasks=next_tasks,
            artifacts={"analysis_result": analysis_result},
            metadata={
                "verdict": analysis_result["verdict"],
                "confidence": analysis_result["confidence"],
                "is_false_positive": analysis_result.get("is_false_positive", False),
            }
        )

    def _rule_based_poc_analysis(
        self,
        stdout: str,
        stderr: str,
        return_code: int,
        crashed: bool,
        vuln_type: str
    ) -> Dict[str, Any]:
        """Rule-based PoC execution result analysis"""

        stdout_lower = (stdout or "").lower()
        stderr_lower = (stderr or "").lower()

        positive_indicators = []
        negative_indicators = []

        # Positive indicators (vulnerability triggered)
        if crashed:
            positive_indicators.append("Process crashed")

        # Check crash address patterns
        crash_patterns = [
            ("0x41414141", "Crash at controlled 32-bit pattern"),
            ("0x4141414141414141", "Crash at controlled 64-bit pattern"),
            ("access violation", "Access violation detected"),
            ("segmentation fault", "Segfault detected"),
        ]
        for pattern, desc in crash_patterns:
            if pattern in stdout_lower or pattern in stderr_lower:
                positive_indicators.append(desc)

        # Negative indicators (possible false positive)
        error_code_patterns = [
            ("returned: 0x1", "Function returned error code"),
            ("returned: 0x80", "Function returned HRESULT error"),
            ("error_", "Error message in output"),
            ("invalid parameter", "Invalid parameter error"),
            ("access denied", "Access denied"),
            ("not found", "Resource not found"),
        ]
        for pattern, desc in error_code_patterns:
            if pattern in stdout_lower or pattern in stderr_lower:
                negative_indicators.append(desc)

        # Determine result
        if crashed and positive_indicators:
            return {
                "vulnerability_triggered": True,
                "verdict": "true_positive",
                "confidence": 0.85,
                "reasoning": f"Crash detected with positive indicators: {', '.join(positive_indicators)}",
                "is_false_positive": False,
                "indicators": {
                    "positive_indicators": positive_indicators,
                    "negative_indicators": negative_indicators
                }
            }

        if not crashed and negative_indicators and not positive_indicators:
            return {
                "vulnerability_triggered": False,
                "verdict": "false_positive",
                "confidence": 0.7,
                "reasoning": f"No crash and function rejected input: {', '.join(negative_indicators)}",
                "is_false_positive": True,
                "indicators": {
                    "positive_indicators": positive_indicators,
                    "negative_indicators": negative_indicators
                }
            }

        return {
            "vulnerability_triggered": False,
            "verdict": "inconclusive",
            "confidence": 0.5,
            "reasoning": "Unable to determine if vulnerability was triggered",
            "is_false_positive": False,
            "indicators": {
                "positive_indicators": positive_indicators,
                "negative_indicators": negative_indicators
            },
            "should_retry": True,
        }

    def _calculate_agent_confidence_adjustment(
        self,
        verdict: str,
        crashed: bool,
        stdout: str,
        analysis_confidence: float
    ) -> float:
        """
        Calculate Agent-driven confidence adjustment value

        Returns a confidence adjustment value based on PoC execution results and Agent verdict.
        Positive values indicate increased confidence, negative values indicate decreased confidence.

        Weight Allocation (Agent-dominated, accounts for 60% of total score):
        - PoC Execution Verification: 30%
        - Agent Intelligent Verdict: 30%

        Args:
            verdict: Agent verdict (true_positive/false_positive/needs_improvement/inconclusive)
            crashed: Whether the PoC caused a crash
            stdout: PoC execution output
            analysis_confidence: Confidence of Agent analysis (0.0-1.0)

        Returns:
            Confidence adjustment value (-0.6 to +0.6)
        """
        adjustment = 0.0
        stdout_lower = (stdout or "").lower()

        # =====================================================================
        # PoC Execution Verification Factors (Weight: 30%)
        # =====================================================================
        if crashed:
            # Check if crash occurred at a controlled address
            controlled_patterns = ["0x41414141", "0x4141414141414141", "0x42424242"]
            is_controlled = any(p in stdout_lower for p in controlled_patterns)

            if is_controlled:
                adjustment += 0.25  # POC_CRASH_CONTROLLED
            else:
                adjustment += 0.10  # POC_CRASH_UNCONTROLLED
        else:
            # Check if an error code was returned
            error_patterns = ["returned: 0x1", "returned: 0x80", "error_", "failed"]
            has_error = any(p in stdout_lower for p in error_patterns)

            if has_error:
                adjustment -= 0.20  # POC_FUNCTION_ERROR
            else:
                adjustment += 0.05  # POC_EXECUTION_OK (Success but no crash)

        # =====================================================================
        # Agent Intelligent Verdict Factors (Weight: 30%)
        # =====================================================================
        if verdict == "true_positive":
            adjustment += 0.25  # AGENT_TRUE_POSITIVE
            # Further adjust based on Agent analysis confidence
            if analysis_confidence >= 0.9:
                adjustment += 0.10  # Extra points for high confidence
        elif verdict == "false_positive":
            adjustment -= 0.40  # AGENT_FALSE_POSITIVE
        elif verdict == "needs_improvement":
            adjustment += 0.0   # AGENT_NEEDS_REVIEW
        else:  # inconclusive
            adjustment -= 0.05  # Slight reduction

        # Limit adjustment range
        adjustment = max(-0.60, min(0.60, adjustment))

        logger.debug(
            f"Agent confidence adjustment: {adjustment:+.2f} "
            f"(verdict={verdict}, crashed={crashed}, analysis_conf={analysis_confidence:.2f})"
        )

        return adjustment

    def _fix_poc_error(self, task: TaskAssignment) -> AgentResult:
        """
        Agent-driven PoC error fixing

        Analyzes Python execution errors and attempts to fix PoC code.
        """
        finding_id = task.parameters.get("finding_id")
        poc_code = task.parameters.get("poc_code", "")
        stderr = task.parameters.get("stderr", "")
        error_type = task.parameters.get("error_type", "UnknownError")
        attempt = task.parameters.get("attempt", 0)
        vuln_type = task.parameters.get("vuln_type", "UNKNOWN")
        target_function = task.parameters.get("target_function", "unknown")

        fix_result = {
            "fixed": False,
            "fixed_poc": None,
            "error_analysis": "",
            "fixes_applied": [],
        }
        next_tasks = []

        # Use LLM for analysis and fixing
        if self.llm_pool is not None and HAVE_PROMPTS and POC_FIX_TEMPLATE:
            try:
                # Extract traceback
                traceback_lines = []
                in_traceback = False
                for line in stderr.split('\n'):
                    if 'traceback' in line.lower():
                        in_traceback = True
                    if in_traceback:
                        traceback_lines.append(line)

                prompt = POC_FIX_TEMPLATE.format(
                    poc_code=poc_code[:5000],  # Limit length
                    stderr=stderr[:2000],
                    error_type=error_type,
                    traceback='\n'.join(traceback_lines[-20:]),  # Last 20 lines
                )

                response = self.call_llm(prompt)
                if response and response.text:
                    llm_result = self._parse_json_response(response.text)
                    if llm_result and llm_result.get("fixes"):
                        fix_result["error_analysis"] = llm_result.get("error_analysis", "")
                        fix_result["root_cause"] = llm_result.get("root_cause", "")

                        # Apply fixes
                        fixed_poc = poc_code
                        for fix in llm_result["fixes"]:
                            original = fix.get("original", "")
                            fixed = fix.get("fixed", "")
                            if original and fixed and original in fixed_poc:
                                fixed_poc = fixed_poc.replace(original, fixed, 1)
                                fix_result["fixes_applied"].append({
                                    "original": original,
                                    "fixed": fixed,
                                    "explanation": fix.get("explanation", "")
                                })

                        if fix_result["fixes_applied"]:
                            fix_result["fixed"] = True
                            fix_result["fixed_poc"] = fixed_poc

                            # Generate re-validation task
                            next_tasks.append(TaskAssignment.create(
                                task_type="validate_poc",
                                parameters={
                                    "finding_id": finding_id,
                                    "poc_code": fixed_poc,
                                    "vuln_type": vuln_type,
                                    "target_function": target_function,
                                    "attempt": attempt,
                                },
                                priority=9,
                            ))
                            logger.info(f"PoC fixed, re-validating (attempt {attempt})")

            except Exception as e:
                logger.warning(f"LLM PoC fix failed: {e}")

        # If LLM cannot fix, use rule-based fixes for common errors
        if not fix_result["fixed"]:
            fixed_poc, fixes = self._apply_common_fixes(poc_code, error_type, stderr)
            if fixes:
                fix_result["fixed"] = True
                fix_result["fixed_poc"] = fixed_poc
                fix_result["fixes_applied"] = fixes

                next_tasks.append(TaskAssignment.create(
                    task_type="validate_poc",
                    parameters={
                        "finding_id": finding_id,
                        "poc_code": fixed_poc,
                        "vuln_type": vuln_type,
                        "target_function": target_function,
                        "attempt": attempt,
                    },
                    priority=9,
                ))

        # Update finding status
        if finding_id:
            if fix_result["fixed"]:
                # PoC fixed, update with fixed code
                self.shared_state.update_finding(
                    finding_id,
                    status="poc_fixed",
                    poc_code=fix_result["fixed_poc"],  # Update to fixed PoC
                    poc_fix_result=fix_result
                )
            else:
                # PoC unfixable, remove invalid PoC (non-functional PoC cannot serve as evidence)
                self.shared_state.update_finding(
                    finding_id,
                    status="poc_unfixable",
                    poc_code=None,  # Delete invalid PoC
                    poc_fix_result=fix_result
                )
                logger.info(f"Finding {finding_id} PoC unfixable, PoC removed")

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=fix_result["fixed"],
            next_tasks=next_tasks,
            artifacts={"fix_result": fix_result},
            metadata={
                "fixed": fix_result["fixed"],
                "fixes_count": len(fix_result["fixes_applied"]),
            }
        )

    def _apply_common_fixes(self, poc_code: str, error_type: str, stderr: str) -> tuple:
        """Apply rule-based fixes for common errors"""
        fixes = []
        fixed_code = poc_code

        # Fix ctypes pointer issues
        if "OverflowError" in error_type or "overflow" in stderr.lower():
            # Add free.argtypes
            if "free(" in fixed_code and "free.argtypes" not in fixed_code:
                old = "free = msvcrt.free"
                new = "free = msvcrt.free\n    free.argtypes = [ctypes.c_void_p]"
                if old in fixed_code:
                    fixed_code = fixed_code.replace(old, new)
                    fixes.append({
                        "original": old,
                        "fixed": new,
                        "explanation": "Added argtypes for free() to handle 64-bit pointers"
                    })

        # Fix ArgumentError parameter type issues
        if "ArgumentError" in error_type:
            # Check if pointer type conversion is needed
            if "ctypes.c_void_p(buf)" not in fixed_code and "free(buf)" in fixed_code:
                old = "free(buf)"
                new = "free(ctypes.c_void_p(buf))"
                fixed_code = fixed_code.replace(old, new)
                fixes.append({
                    "original": old,
                    "fixed": new,
                    "explanation": "Wrap pointer in c_void_p for correct type"
                })

        return fixed_code, fixes

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _parse_json_response(self, response_text: str) -> Optional[Dict]:
        """Parse JSON from LLM response"""
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass

        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        return None

    def _llm_analyze_crash(self, crash_info: Dict[str, Any], rule_based: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """LLM crash analysis"""
        if self.llm_pool is None:
            return None

        prompt = f"""You are a vulnerability analysis expert. Analyze this crash:

Crash Info:
- Exception: {hex(crash_info.get('exception_code', 0)) if crash_info.get('exception_code') else 'Unknown'}
- Fault Address: {hex(crash_info.get('fault_address', 0)) if crash_info.get('fault_address') else 'Unknown'}
- Access Type: {crash_info.get('access_type', 'Unknown')}

Rule-based result: {rule_based}

Respond in JSON:
{{"crash_type": "...", "severity": "Critical|High|Medium|Low", "exploitable": true/false, "root_cause": "...", "confidence": 0.0-1.0}}"""

        try:
            response = self.call_llm(prompt)
            if response and response.text:
                return self._parse_json_response(response.text)
        except Exception as e:
            logger.warning(f"LLM crash analysis error: {e}")

        return None

    # =========================================================================
    # Delegated Task Handling (from AnalyzerAgent)
    # =========================================================================

    def _verify_dangerous_api(self, task: TaskAssignment) -> AgentResult:
        """
        Verify dangerous API calls

        Delegated by AnalyzerAgent to perform deep verification of dangerous API imports.
        Uses symbolic execution and bounds checking to confirm vulnerability exploitability.
        """
        api_name = task.parameters.get("api")
        vuln_type = task.parameters.get("vuln_type", "BUFFER_OVERFLOW")
        address = task.parameters.get("address")
        delegated_from = task.parameters.get("delegated_from")

        logger.info(f"Verifying dangerous API: {api_name} at {address} (from {delegated_from})")

        findings = []
        next_tasks = []

        # 1. Deep verification
        if address:
            verify_result = self.call_tool("deep_verify_vulnerability", {
                "sink_address": address,
                "vuln_type": vuln_type,
            })

            if verify_result and verify_result.success and verify_result.data:
                data = verify_result.data
                confidence = data.get("confidence_score", 0.5)
                is_exploitable = data.get("is_verified", False)

                if is_exploitable or confidence >= 0.5:
                    finding = {
                        "vuln_type": vuln_type,
                        "severity": data.get("confidence_level", "Medium"),
                        "confidence": confidence,
                        "address": address,
                        "sink_api": api_name,
                        "evidence": data.get("evidence", []),
                        "verification_methods": data.get("verification_methods", []),
                        "status": "verified" if is_exploitable else "detected",
                        "verified_by": self.agent_id,
                    }
                    findings.append(finding)

                    # Further verify using symbolic execution for high confidence
                    if confidence >= 0.7 and not data.get("symbolic_verified"):
                        next_tasks.append(TaskAssignment.create(
                            task_type="symbolic_verify",
                            parameters={
                                "sink_address": address,
                                "vuln_type": vuln_type,
                                "api": api_name,
                            },
                            priority=7
                        ))

                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=True,
                    findings=findings,
                    next_tasks=next_tasks,
                    artifacts={"verification_result": data},
                    metadata={
                        "api": api_name,
                        "confidence": confidence,
                        "is_exploitable": is_exploitable,
                    }
                )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=False,
            error=f"Verification failed for API {api_name}"
        )

    def _symbolic_verify(self, task: TaskAssignment) -> AgentResult:
        """
        Symbolic execution verification

        Uses symbolic execution to explore paths from function entry to dangerous sinks,
        solving constraints to confirm vulnerability reachability.
        """
        func_address = task.parameters.get("func_address")
        sink_address = task.parameters.get("sink_address")
        vuln_type = task.parameters.get("vuln_type", "BUFFER_OVERFLOW")
        finding_id = task.parameters.get("finding_id")

        if not func_address or not sink_address:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing func_address or sink_address parameter"
            )

        logger.info(f"Symbolic verification: {func_address} -> {sink_address}")

        # Call symbolic execution tool
        result = self.call_tool("symbolic_explore", {
            "func_address": func_address,
            "target_sink_address": sink_address,
            "num_args": task.parameters.get("num_args", 4),
        })

        findings = []
        next_tasks = []

        if result and result.success and result.data:
            data = result.data
            reachable = data.get("reachable", False)
            paths_found = data.get("paths_to_target", 0)
            solved_inputs = data.get("solved_inputs", {})

            if reachable:
                confidence_boost = data.get("confidence_boost", 0.25)

                finding = {
                    "vuln_type": vuln_type,
                    "severity": "High" if paths_found > 0 else "Medium",
                    "confidence": 0.7 + confidence_boost,
                    "address": sink_address,
                    "function_address": func_address,
                    "evidence": [
                        f"Symbolic execution found {paths_found} paths to sink",
                        f"Path reachability confirmed"
                    ],
                    "status": "verified",
                    "verified_by": self.agent_id,
                }

                if solved_inputs:
                    finding["evidence"].append(f"Concrete trigger inputs found: {len(solved_inputs)} variables")
                    finding["trigger_inputs"] = solved_inputs

                findings.append(finding)

                # Update finding status
                if finding_id:
                    self.shared_state.update_finding(
                        finding_id,
                        status="verified",
                        symbolic_verified=True,
                        paths_to_sink=paths_found,
                        confidence=finding["confidence"],
                    )

                # Symbolic verification complete; no longer delegating PoC generation
                # Verification results are recorded in finding
                logger.info(
                    f"Symbolic verification complete: {paths_found} paths found, "
                    f"confidence={finding['confidence']:.2f}"
                )

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                findings=findings,
                next_tasks=next_tasks,
                artifacts={"symbolic_result": data},
                metadata={
                    "reachable": reachable,
                    "paths_found": paths_found,
                    "has_trigger_inputs": bool(solved_inputs),
                }
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=False,
            error=f"Symbolic verification failed: {result.error if result else 'No result'}"
        )
