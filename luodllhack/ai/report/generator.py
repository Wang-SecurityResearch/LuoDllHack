# -*- coding: utf-8 -*-
"""
luodllhack/ai/report/generator.py
Vulnerability Report Generator

Provides:
- ReportGenerator: Generates structured vulnerability reports
- Report printing and formatting
- Consistency validation
"""

from typing import Dict, List, Any, Optional, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    from ..tools.types import AgentState, VulnReport

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Vulnerability Report Generator

    Responsibilities:
    - Integrate findings into reports
    - Set risk levels
    - Generate recommendations
    - Print formatted reports
    """

    # Mapping of vulnerability types to recommendations
    RECOMMENDATIONS = {
        "BUFFER_OVERFLOW": [
            "Use secure function alternatives (strcpy -> strcpy_s, sprintf -> sprintf_s)",
            "Enable Stack Canaries (/GS)",
            "Enable ASLR and DEP"
        ],
        "FORMAT_STRING": [
            "Use fixed format strings, avoid user input as format parameters"
        ],
        "COMMAND_INJECTION": [
            "Avoid direct concatenation of user input into commands",
            "Use whitelist validation for inputs"
        ],
        "INTEGER_OVERFLOW": [
            "Strictly check integer boundaries before memory allocation or arithmetic operations",
            "Use secure arithmetic libraries (e.g., SafeInt) to prevent overflows"
        ],
        "USE_AFTER_FREE": [
            "Ensure pointers are set to NULL immediately after freeing (p = NULL)",
            "Use smart pointers (RAII) to manage memory lifecycle"
        ],
        "DOUBLE_FREE": [
            "Ensure pointers are set to NULL immediately after freeing (p = NULL)",
            "Use smart pointers (RAII) to manage memory lifecycle"
        ],
    }

    def __init__(self, state: 'AgentState', report: 'VulnReport'):
        """
        Initialize report generator

        Args:
            state: Agent state
            report: Vulnerability report
        """
        self.state = state
        self.report = report

    def finalize(self) -> 'VulnReport':
        """Generate final report"""
        # Integrate findings
        self.report.vulnerabilities = self.state.findings

        # Set risk level
        self._set_risk_level()

        # Generate recommendations
        self.report.recommendations = self._generate_recommendations()

        # Print report
        self.print_report()

        return self.report

    def _set_risk_level(self) -> None:
        """Set risk level based on findings"""
        if not self.state.findings:
            return

        severities = [f.get("severity", "Low") for f in self.state.findings]
        if "Critical" in severities:
            self.report.risk_level = "Critical"
        elif "High" in severities:
            self.report.risk_level = "High"
        elif "Medium" in severities:
            self.report.risk_level = "Medium"

    def _generate_recommendations(self) -> List[str]:
        """Generate hardening recommendations"""
        recs = []
        vuln_types = set(f.get("vuln_type", "") for f in self.state.findings)

        for vuln_type, type_recs in self.RECOMMENDATIONS.items():
            if vuln_type in vuln_types:
                recs.extend(type_recs)

        if not recs:
            if self.state.findings:
                recs.append(f"Perform code review and remediation for {len(self.state.findings)} potential vulnerabilities found")
            else:
                recs.append("No obvious vulnerabilities found during code audit; continuous security testing is recommended")

        return list(set(recs))  # De-duplicate

    def print_report(self) -> None:
        """Print vulnerability report"""
        print("\n" + "=" * 60)
        print("AI Agent Preliminary Report")
        print("=" * 60)

        print(f"\n[Note] This is preliminary data before confidence scoring.")
        print(f"\nPreliminary Risk Level: {self.report.risk_level}")
        print(f"Exploitability: {self.report.exploitability}")
        print(f"Raw Findings: {len(self.report.vulnerabilities)}")
        print(f"PoC Verified: {self.report.poc_verified}")

        if self.report.vulnerabilities:
            print("\nVulnerabilities:")
            for i, vuln in enumerate(self.report.vulnerabilities, 1):
                status = vuln.get('status', 'detected')
                severity = vuln.get('severity', 'N/A')
                vuln_type = vuln.get('vuln_type', 'Unknown')
                print(f"  {i}. [{severity}] {vuln_type} ({status})")
                if 'call_chain' in vuln:
                    print(f"     Chain: {' -> '.join(vuln['call_chain'])}")
                # Only show PoC path for validated vulnerabilities
                if status == "validated" and vuln.get('poc_path'):
                    print(f"     PoC: {vuln['poc_path']}")

        # Show validated PoC summary
        validated_pocs = getattr(self.report, 'validated_pocs', [])
        if validated_pocs:
            print("\nValidated PoCs (Evidence):")
            for poc_info in validated_pocs:
                print(f"  - {poc_info['vuln_type']} @ {poc_info['function']}")
                print(f"    Path: {poc_info['poc_path']}")

        if self.report.recommendations:
            print("\nRecommendations:")
            for rec in self.report.recommendations:
                print(f"  - {rec}")

        print(f"\nAnalysis Steps: {self.state.current_step}")
        print(f"Tools Called: {len(self.state.actions)}")

    def validate_consistency(self, scored_findings: Optional[List] = None) -> List[str]:
        """
        Validate report data consistency

        Args:
            scored_findings: List of findings after confidence scoring

        Returns:
            List of warning messages
        """
        warnings = []

        header_count = len(self.report.vulnerabilities)
        scored_count = len(scored_findings) if scored_findings else -1

        # Check for risk level and findings mismatch
        if self.report.risk_level in ["High", "Critical"]:
            if scored_count == 0:
                warnings.append(
                    f"Risk level '{self.report.risk_level}' based on preliminary data, "
                    f"but all findings were filtered after AI review"
                )

        # Check PoC verification status
        if self.report.poc_verified and header_count == 0:
            warnings.append("PoC marked as verified but no vulnerabilities to verify")

        if warnings:
            print("\n[Consistency Check] Warnings:")
            for w in warnings:
                print(f"  - {w}")

        return warnings

    @staticmethod
    def convert_orchestrator_findings(findings: List[Any], state: 'AgentState', report: 'VulnReport') -> None:
        """
        Convert Orchestrator Findings to report format

        Args:
            findings: List of Orchestrator Findings
            state: Agent state
            report: Vulnerability report
        """
        validated_pocs = []  # Only collect validated PoCs

        for finding in findings:
            finding_dict = {
                "type": "orchestrator_finding",
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "address": finding.address,
                "function": finding.function,
                "sink_api": finding.sink_api,
                "status": finding.status,
                "evidence": finding.evidence,
                "cwe_id": finding.cwe_id,
            }

            # Only retain PoC path as evidence for validated vulnerabilities
            if finding.status == "validated":
                poc_path = getattr(finding, 'poc_path', None)
                if poc_path:
                    finding_dict["poc_path"] = poc_path
                    validated_pocs.append({
                        "vuln_type": finding.vuln_type,
                        "function": finding.function,
                        "poc_path": poc_path,
                    })
                if finding.poc_code:
                    finding_dict["poc_code"] = finding.poc_code

            state.findings.append(finding_dict)

        # Set PoC information in report - only includes validated PoCs
        if validated_pocs:
            report.validated_pocs = validated_pocs
            report.poc_verified = True
            # Use the first validated PoC as the primary PoC
            first_poc = validated_pocs[0]
            if 'poc_code' in state.findings[0]:
                report.poc_code = state.findings[0].get('poc_code')
        else:
            report.validated_pocs = []
            report.poc_verified = False
