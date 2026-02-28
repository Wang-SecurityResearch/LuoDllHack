# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/critic.py
Critic Agent - Responsible for quality review and evidence chain verification

Responsibilities:
    - Quality review of analysis reports
    - Verification of evidence chain integrity
    - False positive/false negative detection
    - Final verdict
    - [P3] Intelligent review driven by LLM
"""

from typing import Dict, List, Any, Optional
import logging
import json

from .base import (
    BaseAgent,
    AgentCapability,
    TaskAssignment,
    AgentResult,
)
from .prompt_engineering import FINDING_REVIEW_TEMPLATE, POC_REVIEW_TEMPLATE

logger = logging.getLogger(__name__)

# =============================================================================
# False Positive Detection Rules
# =============================================================================

# Known framework entry point functions (usually false positives)
KNOWN_ENTRY_POINTS = {
    # Windows entry point
    "main", "wmain", "_main", "_wmain",
    "WinMain", "wWinMain", "_WinMain", "_wWinMain",
    "DllMain", "_DllMain", "DllEntryPoint",
    # Chromium/CEF entry point
    "ChromeMain", "CefMain", "CefExecuteProcess",
    "chrome_main", "cef_main",
    # Qt entry points
    "qt_main", "qtmain",
    # Other frameworks
    "NSApplicationMain", "UIApplicationMain",
    "JNI_OnLoad", "JNI_OnUnload",
}

# Known secure modules and libraries (high probability of false positives)
KNOWN_SECURE_MODULES = {
    # Browser engine
    "chromium", "chrome", "cef", "electron", "webkit",
    # Security library
    "openssl", "libssl", "libcrypto", "boringssl",
    "mbedtls", "wolfssl", "gnutls",
    # System core
    "ntdll", "kernel32", "kernelbase", "ntoskrnl",
}

# Rules for combining vulnerability types and entry points
# Certain vulnerability types detected in entry point functions are usually false positives.
ENTRY_POINT_FP_VULN_TYPES = {
    "UNINITIALIZED_MEMORY",
    "BUFFER_OVERFLOW",
    "STACK_OVERFLOW",
    "INTEGER_OVERFLOW",
    "NULL_POINTER",
}

# PoC execution failure patterns (indicating potential false positives)
POC_FAILURE_PATTERNS = [
    "access violation",
    "segmentation fault",
    "before reaching",
    "failed to load",
    "dll not found",
    "module not found",
    "entry point not found",
    "initialization failed",
]



class CriticAgent(BaseAgent):
    """
    Quality Assurance Agent

    Focuses on reviewing analysis quality and ensuring the reliability of findings.

    Capabilities:
        - REVIEW: Quality review

    Handled task types:
        - review_finding: Review a single finding
        - verify_evidence_chain: Verify evidence chain
        - final_verdict: Final verdict
        - review_report: Review complete report
    """

    def __init__(self, agent_id: str, *args, **kwargs):
        capabilities = kwargs.pop("capabilities", [AgentCapability.REVIEW])

        # Extract agent_registry (BaseAgent does not accept this parameter)
        self.agent_registry = kwargs.pop("agent_registry", None)

        super().__init__(
            agent_id=agent_id,
            capabilities=capabilities,
            *args,
            **kwargs
        )

        self._task_handlers = {
            "review_finding": self._review_finding,
            "verify_evidence_chain": self._verify_evidence_chain,
            "final_verdict": self._final_verdict,
            "review_report": self._review_report,
            "quality_check": self._quality_check,
            # [P3] LLM-driven review tasks
            "llm_review_finding": self._llm_review_finding,
            "llm_review_poc": self._llm_review_poc,
        }

        self._task_confidence = {
            "review_finding": 0.95,
            "verify_evidence_chain": 0.90,
            "final_verdict": 0.95,
            "review_report": 0.90,
            "quality_check": 0.85,
            "llm_review_finding": 0.92,
            "llm_review_poc": 0.90,
        }

        # Quality criteria
        self._quality_criteria = {
            "min_confidence": 0.5,
            "require_evidence": True,
            "require_verification": True,
            "max_unverified_ratio": 0.3,
        }
        
        # Register tools needed for ReAct mode
        self.register_tool_for_llm(
            "analyze_code_structure",
            "Analyze the code structure around a specific address/function",
            {"address": "Target address or function name", "context_lines": "Number of lines (default 20)"}
        )
        self.register_tool_for_llm(
            "check_fp_rules",
            "Check against known false positive rules",
            {"finding_id": "ID of the finding to check"}
        )
        self.register_tool_for_llm(
            "search_similar_findings",
            "Search for similar findings in the knowledge base",
            {"vuln_type": "Type of vulnerability", "function": "Function name"}
        )
        
        # Map complex tasks to ReAct handlers
        self._task_handlers["complex_verdict"] = self.process_task_with_react
        self._task_handlers["deep_review"] = self.process_task_with_react
        self._task_confidence["complex_verdict"] = 0.90
        self._task_confidence["deep_review"] = 0.90

    @property
    def role(self) -> str:
        return "critic"

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
    # Task Handlers
    # =========================================================================

    def _review_finding(self, task: TaskAssignment) -> AgentResult:
        """
        Review a single finding

        Check the quality and reliability of a finding.
        """
        finding_id = task.parameters.get("finding_id")

        if not finding_id:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing finding_id parameter"
            )

        finding = self.shared_state.get_finding(finding_id)
        if not finding:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Finding not found: {finding_id}"
            )

        review = {
            "passed": True,
            "issues": [],
            "score": 1.0,
            "recommendation": "accept",
        }

        # Check confidence
        if finding.confidence < self._quality_criteria["min_confidence"]:
            review["issues"].append(f"Low confidence: {finding.confidence:.2f}")
            review["score"] -= 0.3

        # Check evidence
        if self._quality_criteria["require_evidence"]:
            if not finding.evidence or len(finding.evidence) == 0:
                review["issues"].append("Missing evidence")
                review["score"] -= 0.3

        # Check verification status
        if self._quality_criteria["require_verification"]:
            if finding.status not in ["verified", "validated", "exploited"]:
                review["issues"].append(f"Unverified status: {finding.status}")
                review["score"] -= 0.2

        # Check mandatory fields
        if not finding.address:
            review["issues"].append("Missing vulnerability address")
            review["score"] -= 0.2

        if not finding.vuln_type:
            review["issues"].append("Missing vulnerability type")
            review["score"] -= 0.1

        # Determine pass/reject
        review["score"] = max(0.0, review["score"])
        if review["score"] < 0.5:
            review["passed"] = False
            review["recommendation"] = "reject"
        elif review["score"] < 0.7:
            review["recommendation"] = "needs_work"

        # Update shared state
        self.shared_state.update_finding(
            finding_id,
            reviewed_by=self.agent_id,
            review_score=review["score"],
            review_issues=review["issues"]
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"review": review},
            metadata={
                "passed": review["passed"],
                "score": review["score"],
                "issue_count": len(review["issues"]),
            }
        )

    def _verify_evidence_chain(self, task: TaskAssignment) -> AgentResult:
        """
        Verify evidence chain

        Ensures a complete evidence chain from source to sink.
        """
        finding_id = task.parameters.get("finding_id")

        if not finding_id:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing finding_id parameter"
            )

        finding = self.shared_state.get_finding(finding_id)
        if not finding:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Finding not found: {finding_id}"
            )

        chain_verification = {
            "complete": False,
            "links": [],
            "gaps": [],
            "strength": 0.0,
        }

        # Check each link in the evidence chain
        evidence = finding.evidence or []

        # Expected links in the evidence chain
        expected_links = [
            "source_identification",  # Taint source identification
            "taint_propagation",      # Taint propagation
            "sink_reached",           # Reached dangerous function
            "bounds_check_absent",    # No bounds check
            "exploitability",         # Exploitability
        ]

        found_links = set()
        for e in evidence:
            # Parse evidence type
            e_lower = e.lower() if isinstance(e, str) else str(e).lower()
            if "source" in e_lower or "parameter" in e_lower or "input" in e_lower:
                found_links.add("source_identification")
            if "taint" in e_lower or "propagate" in e_lower or "flow" in e_lower:
                found_links.add("taint_propagation")
            if "sink" in e_lower or "dangerous" in e_lower or "api" in e_lower:
                found_links.add("sink_reached")
            if "bound" in e_lower or "check" in e_lower or "no validation" in e_lower:
                found_links.add("bounds_check_absent")
            if "exploit" in e_lower or "poc" in e_lower or "crash" in e_lower:
                found_links.add("exploitability")

        chain_verification["links"] = list(found_links)
        chain_verification["gaps"] = [l for l in expected_links if l not in found_links]
        chain_verification["strength"] = len(found_links) / len(expected_links)
        chain_verification["complete"] = len(chain_verification["gaps"]) == 0

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"chain_verification": chain_verification},
            metadata={
                "chain_complete": chain_verification["complete"],
                "strength": chain_verification["strength"],
                "gap_count": len(chain_verification["gaps"]),
            }
        )

    def _final_verdict(self, task: TaskAssignment) -> AgentResult:
        """
        Final verdict

        Integrates all information to make a final judgment.
        If LLM is available, perform deep review with LLM first.
        """
        finding_id = task.parameters.get("finding_id")

        if not finding_id:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing finding_id parameter"
            )

        # Phase 3: Get current version for optimistic locking
        state_version = self.shared_state.get_version()

        finding = self.shared_state.get_finding(finding_id)
        if not finding:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Finding not found: {finding_id}"
            )

        # If LLM is available, conduct LLM review first
        llm_review_result = None
        if self.llm_pool is not None:
            logger.info(f"Using LLM for final verdict on {finding_id}")
            try:
                llm_task = TaskAssignment.create(
                    task_type="llm_review_finding",
                    parameters={"finding_id": finding_id}
                )
                llm_task.task_id = task.task_id + "_llm"
                llm_result = self._llm_review_finding(llm_task)
                if llm_result.success and llm_result.artifacts:
                    llm_review_result = llm_result.artifacts.get("llm_review", {})
            except Exception as e:
                logger.warning(f"LLM review failed, using rule-based: {e}")

        verdict = {
            "decision": "undetermined",
            "confidence": 0.0,
            "reasoning": [],
            "final_severity": finding.severity,
            "llm_reviewed": llm_review_result is not None,
            "fp_detection": None,
            "agent_driven": True,  # Flag as agent-driven verdict
        }

        # =====================================================================
        # Agent-driven scoring (Agent-centric, accounts for 60%)
        # =====================================================================
        # Get PoC verification result from ValidationAgent
        validation_result = getattr(finding, 'validation_result', None)
        poc_verdict = None
        if validation_result and isinstance(validation_result, dict):
            poc_verdict = validation_result.get("verdict")

        # Base score starts from finding's current confidence (includes static analysis + Agent adjustments)
        score = finding.confidence if finding.confidence else 0.4

        # =====================================================================
        # Core: PoC verification result (Weight 35%)
        # =====================================================================
        if poc_verdict:
            if poc_verdict == "true_positive":
                score += 0.35
                verdict["reasoning"].append("[Agent] PoC validation: TRUE POSITIVE (+35%)")
            elif poc_verdict == "false_positive":
                score -= 0.40
                verdict["reasoning"].append("[Agent] PoC validation: FALSE POSITIVE (-40%)")
            elif poc_verdict == "needs_improvement":
                score -= 0.05
                verdict["reasoning"].append("[Agent] PoC validation: needs improvement (-5%)")
            elif poc_verdict == "inconclusive":
                score -= 0.10
                verdict["reasoning"].append("[Agent] PoC validation: inconclusive (-10%)")
        else:
            # No PoC verification results
            verdict["reasoning"].append("[Agent] No PoC validation result")

        # =====================================================================
        # Rule false positive detection (weight 15%)
        # =====================================================================
        fp_result = self._detect_false_positive(finding)
        verdict["fp_detection"] = fp_result

        if fp_result["is_likely_fp"]:
            # Rule detected as FP, but weight is reduced (Agent-centric)
            penalty = fp_result["confidence_penalty"] * 0.5  # Reduce rule weight
            score -= penalty
            verdict["reasoning"].append(
                f"[Rule] Likely false positive (FP score: {fp_result['fp_score']:.2f}, penalty: -{penalty:.2f})"
            )
        elif fp_result["fp_score"] >= 0.3:
            penalty = fp_result["confidence_penalty"] * 0.5
            score -= penalty
            verdict["reasoning"].append(
                f"[Rule] Potential FP indicators (FP score: {fp_result['fp_score']:.2f})"
            )

        # =====================================================================
        # LLM Deep Review (Weight 25%)
        # =====================================================================
        if llm_review_result:
            if llm_review_result.get("is_valid", True):
                score += 0.20  # Increase LLM validation weight
                verdict["reasoning"].append("[LLM] Finding validated (+20%)")
            else:
                score -= 0.20
                verdict["reasoning"].append("[LLM] Finding rejected (-20%)")

            # Apply LLM confidence adjustment
            conf_adj = llm_review_result.get("confidence_adjustment", 0)
            score += conf_adj
            if conf_adj != 0:
                verdict["reasoning"].append(f"[LLM] Confidence adjustment: {conf_adj:+.2f}")

            # Record LLM suggestions
            if llm_review_result.get("suggestions"):
                verdict["llm_suggestions"] = llm_review_result["suggestions"]

            # Integrate LLM FP validation
            fp_validation = llm_review_result.get("fp_validation", {})
            if fp_validation:
                llm_fp_confidence = fp_validation.get("fp_confidence", 0.0)
                agrees_with_detection = fp_validation.get("agrees_with_detection", True)
                additional_indicators = fp_validation.get("additional_fp_indicators", [])

                # When LLM and rule detection disagree, LLM takes precedence
                if not agrees_with_detection and fp_result["is_likely_fp"]:
                    score += 0.15  # LLM thinks it's not FP, override rule
                    verdict["reasoning"].append("[LLM] Overrides rule FP detection - likely true positive (+15%)")
                elif agrees_with_detection and not fp_result["is_likely_fp"] and llm_fp_confidence >= 0.5:
                    score -= 0.20  # LLM thinks it's an FP
                    verdict["reasoning"].append(f"[LLM] Identified as FP (confidence: {llm_fp_confidence:.2f}) (-20%)")

                if additional_indicators:
                    score -= 0.05 * len(additional_indicators[:3])
                    verdict["reasoning"].append(f"[LLM] Additional FP indicators: {', '.join(additional_indicators[:2])}")

                verdict["llm_fp_confidence"] = llm_fp_confidence

        # =====================================================================
        # Static factors (Weight 25% - Reduced static factor weight)
        # =====================================================================
        # Verification status (Weight 15%)
        status_scores = {
            "validated": 0.15,       # Decrease
            "exploited": 0.15,       # Reduce
            "verified": 0.10,        # Reduce
            "false_positive": -0.30, # Agent marked FP
            "detected": 0.0,
            "rejected": -0.25,
            "poc_failed": -0.10,     # Reduce
            "inconclusive": -0.05,
        }
        status_score = status_scores.get(finding.status, 0)
        score += status_score
        verdict["reasoning"].append(f"[Static] Status: {finding.status} ({status_score:+.2f})")

        # Number of evidence items (Weight 5%)
        evidence_count = len(finding.evidence) if finding.evidence else 0
        if evidence_count >= 3:
            score += 0.05
            verdict["reasoning"].append(f"[Static] Strong evidence ({evidence_count} items) (+5%)")
        elif evidence_count == 0:
            score -= 0.05
            verdict["reasoning"].append("[Static] No evidence (-5%)")

        # Existence of PoC code (Weight 5%)
        if finding.poc_code:
            score += 0.05
            verdict["reasoning"].append("[Static] PoC code available (+5%)")

        # Limit range and determine verdict
        score = max(0.0, min(1.0, score))
        verdict["confidence"] = score

        if score >= 0.7:
            verdict["decision"] = "confirmed_vulnerability"
            verdict["final_severity"] = finding.severity
        elif score >= 0.5:
            verdict["decision"] = "likely_vulnerability"
            # Possible severity downgrade
            if finding.severity == "Critical":
                verdict["final_severity"] = "High"
        elif score >= 0.3:
            verdict["decision"] = "possible_vulnerability"
            verdict["final_severity"] = "Medium"
        else:
            verdict["decision"] = "likely_false_positive"
            verdict["final_severity"] = "Low"

        # Phase 3: Use optimistic locking to update shared state
        is_false_positive = verdict["decision"] == "likely_false_positive"
        final_confidence = score if not is_false_positive else min(score, 0.2)

        update_success, updated_finding = self.shared_state.compare_and_update_finding(
            expected_version=state_version,
            finding_id=finding_id,
            updates={
                "final_verdict": verdict["decision"],
                "final_severity": verdict["final_severity"],
                "verdict_confidence": score,
                "confidence": final_confidence,
                "status": "rejected" if is_false_positive else finding.status,
            }
        )

        if not update_success:
            # Optimistic lock failed, state modified by another Agent
            logger.warning(f"Optimistic lock failed for {finding_id}, state was modified by another agent")
            # Fallback to normal update (or choose to retry)
            self.shared_state.update_finding(
                finding_id,
                final_verdict=verdict["decision"],
                final_severity=verdict["final_severity"],
                verdict_confidence=score
            )

        # Update AI review status - if it is FP, update confidence and status
        review_reasons = verdict["reasoning"] if is_false_positive else None

        self.shared_state.update_finding_review_status(
            finding_id=finding_id,
            is_false_positive=is_false_positive,
            review_reasons=review_reasons,
            final_confidence=final_confidence
        )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"verdict": verdict},
            metadata={
                "decision": verdict["decision"],
                "confidence": verdict["confidence"],
                "severity": verdict["final_severity"],
            }
        )

    def _review_report(self, task: TaskAssignment) -> AgentResult:
        """
        Review complete report

        Assesses the quality of the entire analysis report.
        """
        # Get all findings
        all_findings = self.shared_state.get_all_findings()

        report_review = {
            "total_findings": len(all_findings),
            "reviewed_count": 0,
            "passed_count": 0,
            "failed_count": 0,
            "overall_quality": 0.0,
            "issues": [],
            "recommendations": [],
        }

        if not all_findings:
            report_review["issues"].append("No findings to review")
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                artifacts={"report_review": report_review},
            )

        total_score = 0.0

        for finding in all_findings:
            finding_score = finding.confidence

            # Check various quality metrics
            if finding.evidence and len(finding.evidence) > 0:
                finding_score += 0.1
            if finding.status in ["verified", "validated", "exploited"]:
                finding_score += 0.2
            if finding.poc_code:
                finding_score += 0.1

            finding_score = min(1.0, finding_score)
            total_score += finding_score
            report_review["reviewed_count"] += 1

            if finding_score >= 0.5:
                report_review["passed_count"] += 1
            else:
                report_review["failed_count"] += 1

        # Calculate overall quality
        report_review["overall_quality"] = total_score / len(all_findings)

        # Generate recommendations
        unverified_ratio = 1 - (report_review["passed_count"] / len(all_findings))
        if unverified_ratio > self._quality_criteria["max_unverified_ratio"]:
            report_review["recommendations"].append(
                f"Too many unverified findings ({unverified_ratio:.1%}). Consider additional verification."
            )

        if report_review["overall_quality"] < 0.5:
            report_review["recommendations"].append(
                "Overall report quality is low. Review and enhance evidence collection."
            )

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"report_review": report_review},
            metadata={
                "overall_quality": report_review["overall_quality"],
                "pass_rate": report_review["passed_count"] / max(1, len(all_findings)),
            }
        )

    def _quality_check(self, task: TaskAssignment) -> AgentResult:
        """
        Quick quality check

        Fast quality assessment of a single finding.
        """
        finding_data = task.parameters.get("finding", {})

        if not finding_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing finding parameter"
            )

        quality = {
            "acceptable": True,
            "score": 0.0,
            "flags": [],
        }

        score = 0.5

        # Check basic fields
        if finding_data.get("address"):
            score += 0.1
        else:
            quality["flags"].append("missing_address")

        if finding_data.get("vuln_type"):
            score += 0.1
        else:
            quality["flags"].append("missing_vuln_type")

        if finding_data.get("confidence", 0) >= 0.5:
            score += 0.2
        else:
            quality["flags"].append("low_confidence")

        if finding_data.get("evidence"):
            score += 0.1
        else:
            quality["flags"].append("missing_evidence")

        quality["score"] = min(1.0, score)
        quality["acceptable"] = len(quality["flags"]) <= 1 and score >= 0.5

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=True,
            artifacts={"quality": quality},
            metadata={
                "acceptable": quality["acceptable"],
                "score": quality["score"],
            }
        )

    # =========================================================================
    # [P3] LLM-driven review tasks
    # =========================================================================

    def _llm_review_finding(self, task: TaskAssignment) -> AgentResult:
        """
        Review vulnerability findings using LLM

        LLM evaluates the validity of findings and provides improvement suggestions.
        """
        finding_id = task.parameters.get("finding_id")
        finding_data = task.parameters.get("finding", {})
        finding = None

        # Get from shared_state or use passed data
        if finding_id and not finding_data:
            finding = self.shared_state.get_finding(finding_id)
            if finding:
                finding_data = {
                    "vuln_type": finding.vuln_type,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "address": finding.address,
                    "function": finding.function,
                    "sink_api": getattr(finding, 'sink_api', 'unknown'),
                    "status": finding.status,
                    "evidence": finding.evidence,
                    "poc_code": finding.poc_code,
                }

        if not finding_data:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing finding data"
            )

        # Check if LLM is available
        if self.llm_pool is None:
            logger.warning(f"Agent {self.agent_id} has no LLM, falling back to rule-based review")
            return self._review_finding(task)

        # =====================================================================
        # Run false positive detection (if finding object exists)
        # =====================================================================
        fp_result = {"fp_score": 0.0, "is_likely_fp": False, "reasons": []}
        if finding:
            fp_result = self._detect_false_positive(finding)
        
        # Format FP reasons as a string
        fp_reasons_str = "; ".join(fp_result["reasons"]) if fp_result["reasons"] else "None"

        # Build prompt (includes FP detection results)
        # Build prompt (including FP detection results)
        prompt = FINDING_REVIEW_TEMPLATE.format(
            vuln_type=finding_data.get("vuln_type", "unknown"),
            severity=finding_data.get("severity", "unknown"),
            confidence=finding_data.get("confidence", 0.5),
            address=finding_data.get("address", "unknown"),
            function=finding_data.get("function", "unknown"),
            sink_api=finding_data.get("sink_api", "unknown"),
            status=finding_data.get("status", "unknown"),
            evidence=finding_data.get("evidence", []),
            fp_score=fp_result["fp_score"],
            is_likely_fp=fp_result["is_likely_fp"],
            fp_reasons=fp_reasons_str,
        )

        # Call LLM
        try:
            response = self.call_llm(prompt)
            if response is None or response.text is None:
                logger.warning("LLM returned empty response, falling back to rule-based")
                return self._review_finding(task)

            # Parse JSON response
            llm_review = self._parse_json_response(response.text)
            if llm_review is None:
                logger.warning("Failed to parse LLM response, falling back to rule-based")
                return self._review_finding(task)

            # Apply LLM review results
            new_confidence = finding_data.get("confidence", 0.5) + llm_review.get("confidence_adjustment", 0)
            new_confidence = max(0.0, min(1.0, new_confidence))

            review_result = {
                "llm_reviewed": True,
                "is_valid": llm_review.get("is_valid", True),
                "quality_score": llm_review.get("quality_score", 0.5),
                "confidence_adjustment": llm_review.get("confidence_adjustment", 0),
                "new_confidence": new_confidence,
                "missing_evidence": llm_review.get("missing_evidence", []),
                "suggestions": llm_review.get("suggestions", []),
                "reasoning": llm_review.get("reasoning", ""),
                "fp_validation": llm_review.get("fp_validation", {}),  # New: LLM's FP validation
            }

            # Update shared state
            if finding_id:
                self.shared_state.update_finding(
                    finding_id,
                    reviewed_by=self.agent_id,
                    llm_reviewed=True,
                    review_score=review_result["quality_score"],
                    confidence=new_confidence
                )

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                artifacts={"llm_review": review_result},
                metadata={
                    "llm_reviewed": True,
                    "is_valid": review_result["is_valid"],
                    "quality_score": review_result["quality_score"],
                    "fp_validated": bool(review_result["fp_validation"]),
                }
            )

        except Exception as e:
            logger.error(f"LLM review failed: {e}")
            return self._review_finding(task)

    def _llm_review_poc(self, task: TaskAssignment) -> AgentResult:
        """
        Review PoC code using LLM

        LLM checks if the PoC is likely to work and provides improvement suggestions.
        """
        poc_code = task.parameters.get("poc_code", "")
        vuln_type = task.parameters.get("vuln_type", "unknown")
        function = task.parameters.get("function", "unknown")
        confidence = task.parameters.get("confidence", 0.5)
        finding_id = task.parameters.get("finding_id")

        if not poc_code:
            # Try to get from finding
            if finding_id:
                finding = self.shared_state.get_finding(finding_id)
                if finding and finding.poc_code:
                    poc_code = finding.poc_code
                    vuln_type = finding.vuln_type
                    function = finding.function
                    confidence = finding.confidence

        if not poc_code:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="Missing PoC code"
            )

        # Check if LLM is available
        if self.llm_pool is None:
            logger.warning(f"Agent {self.agent_id} has no LLM for PoC review")
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error="No LLM available for PoC review"
            )

        # Build prompt
        prompt = POC_REVIEW_TEMPLATE.format(
            poc_code=poc_code[:4000],  # Limit length
            vuln_type=vuln_type,
            function=function,
            confidence=confidence,
        )

        # Call LLM
        try:
            response = self.call_llm(prompt)
            if response is None or response.text is None:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error="LLM returned empty response"
                )

            # Parse JSON response
            llm_review = self._parse_json_response(response.text)
            if llm_review is None:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    success=False,
                    error="Failed to parse LLM response"
                )

            poc_review = {
                "llm_reviewed": True,
                "likely_to_work": llm_review.get("likely_to_work", False),
                "quality_score": llm_review.get("quality_score", 0.5),
                "issues": llm_review.get("issues", []),
                "improvements": llm_review.get("improvements", []),
                "critical_issues": llm_review.get("critical_issues", []),
            }

            # If there are serious issues, suggest regeneration
            next_tasks = []
            if poc_review["critical_issues"] and finding_id:
                next_tasks.append(TaskAssignment.create(
                    task_type="regenerate_poc",
                    parameters={
                        "finding_id": finding_id,
                        "issues": poc_review["critical_issues"],
                        "improvements": poc_review["improvements"],
                    },
                    priority=7
                ))

            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=True,
                artifacts={"poc_review": poc_review},
                next_tasks=next_tasks,
                metadata={
                    "llm_reviewed": True,
                    "likely_to_work": poc_review["likely_to_work"],
                    "quality_score": poc_review["quality_score"],
                    "has_critical_issues": len(poc_review["critical_issues"]) > 0,
                }
            )

        except Exception as e:
            logger.error(f"LLM PoC review failed: {e}")
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"LLM review failed: {str(e)}"
            )

    def _parse_json_response(self, response_text: str) -> Optional[Dict]:
        """Parse JSON from LLM response"""
        import re

        # Try parsing directly
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON block
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        return None

    # =========================================================================
    # False positive detection
    # =========================================================================

    def _detect_false_positive(self, finding) -> Dict[str, Any]:
        """
        Detect if a finding is likely to be a false positive

        Args:
            finding: Vulnerability finding object

        Returns:
            {
                "is_likely_fp": bool,
                "fp_score": float (0.0-1.0, higher means more likely to be an FP),
                "reasons": list of reasons,
                "confidence_penalty": float (degree to which confidence should be reduced)
            }
        """
        result = {
            "is_likely_fp": False,
            "fp_score": 0.0,
            "reasons": [],
            "confidence_penalty": 0.0,
        }

        fp_score = 0.0
        function_name = finding.function or ""
        vuln_type = finding.vuln_type or ""
        status = finding.status or ""
        dll_name = ""

        # Extract DLL name from address or other fields
        if hasattr(finding, 'binary_path') and finding.binary_path:
            dll_name = finding.binary_path.lower().split("\\")[-1].split("/")[-1]
        elif hasattr(finding, 'module') and finding.module:
            dll_name = finding.module.lower()

        # =====================================================================
        # Rule 1: Entry point function detection
        # =====================================================================
        if function_name in KNOWN_ENTRY_POINTS:
            fp_score += 0.4
            result["reasons"].append(f"Target is a known entry point function: {function_name}")

            # If vuln type is common FP type for entry points, further increase score
            if vuln_type.upper() in ENTRY_POINT_FP_VULN_TYPES:
                fp_score += 0.2
                result["reasons"].append(
                    f"Vulnerability type '{vuln_type}' at entry point is commonly a false positive"
                )

        # =====================================================================
        # Rule 2: Well-known secure module detection
        # =====================================================================
        dll_base = dll_name.replace(".dll", "").replace(".exe", "").lower()
        for secure_module in KNOWN_SECURE_MODULES:
            if secure_module in dll_base:
                fp_score += 0.25
                result["reasons"].append(
                    f"Target is in a well-audited module: {dll_name} (contains '{secure_module}')"
                )
                break

        # =====================================================================
        # Rule 3: PoC execution status detection
        # =====================================================================
        if status == "poc_failed":
            fp_score += 0.15
            result["reasons"].append("PoC execution failed")

            # Check failure reason
            validation_result = getattr(finding, 'validation_result', {}) or {}
            crash_info = validation_result.get("crash_info", {})
            stderr = crash_info.get("stderr", "") or validation_result.get("error", "")

            if stderr:
                stderr_lower = stderr.lower()
                for pattern in POC_FAILURE_PATTERNS:
                    if pattern in stderr_lower:
                        fp_score += 0.1
                        result["reasons"].append(f"PoC failed with pattern: '{pattern}'")
                        break

        # =====================================================================
        # Rule 4: Lack of verification evidence
        # =====================================================================
        if status in ["detected", "unverified"]:
            if not finding.evidence or len(finding.evidence) == 0:
                fp_score += 0.15
                result["reasons"].append("No supporting evidence and not verified")

        # =====================================================================
        # Rule 5: Simple pattern matching in large DLLs
        # =====================================================================
        # Findings from simple static analysis in large DLLs (like Chromium) are more likely to be FPs.
        large_dll_indicators = ["chrome", "chromium", "electron", "cef", "webkit", "v8"]
        for indicator in large_dll_indicators:
            if indicator in dll_base:
                # If confidence is low, more likely to be an FP
                if finding.confidence < 0.7:
                    fp_score += 0.15
                    result["reasons"].append(
                        f"Low confidence finding in large framework ({indicator})"
                    )
                break

        # =====================================================================
        # Rule 6: Function name pattern detection
        # =====================================================================
        # Certain function name patterns are usually safe
        safe_function_patterns = [
            "init", "initialize", "setup", "start", "main", "entry",
            "create", "new", "alloc", "malloc",  # Allocation functions themselves are usually not vulnerabilities
        ]
        func_lower = function_name.lower()
        for pattern in safe_function_patterns:
            if func_lower.startswith(pattern) or func_lower.endswith(pattern):
                if vuln_type.upper() in ["UNINITIALIZED_MEMORY", "NULL_POINTER"]:
                    fp_score += 0.1
                    result["reasons"].append(
                        f"Function name pattern '{pattern}' with vuln type '{vuln_type}' is often FP"
                    )
                break

        # =====================================================================
        # Calculate final result
        # =====================================================================
        fp_score = min(1.0, fp_score)  # Limit maximum value
        result["fp_score"] = fp_score
        result["is_likely_fp"] = fp_score >= 0.5

        # Calculate confidence penalty
        if fp_score >= 0.7:
            result["confidence_penalty"] = 0.4
        elif fp_score >= 0.5:
            result["confidence_penalty"] = 0.25
        elif fp_score >= 0.3:
            result["confidence_penalty"] = 0.1

        if result["reasons"]:
            logger.info(
                f"False positive detection for {finding.finding_id}: "
                f"score={fp_score:.2f}, reasons={result['reasons']}"
            )

        return result
