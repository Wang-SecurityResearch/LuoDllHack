# -*- coding: utf-8 -*-
"""Parse LuoDllHack JSON vulnerability reports."""

import json
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path


@dataclass
class Finding:
    """Normalized vulnerability finding"""
    id: str                          # Unique identifier
    address: int                     # Vulnerability address
    vuln_type: str                   # e.g., "BUFFER_OVERFLOW"
    confidence: float                # 0.0 - 1.0
    severity: str = "Medium"         # Critical/High/Medium/Low
    sink_api: str = ""               # e.g., "strcpy"
    function: str = ""               # Function name
    cwe_id: str = ""                 # e.g., "CWE-120"
    # Verification status
    status: str = "pending"          # pending/verifying/verified
    verdict: str = ""                # true_positive/false_positive/inconclusive
    verdict_confidence: float = 0.0
    verdict_reasoning: str = ""


class ReportParser:
    """Parse LuoDllHack vulnerability reports (both formats)"""

    @staticmethod
    def load(path: str) -> List[Finding]:
        """Load report and return normalized findings"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Detect format and parse
        if "findings" in data and isinstance(data["findings"], list):
            if data["findings"] and "location" in data["findings"][0]:
                # Algorithm mode format
                return ReportParser._parse_algorithm_format(data)
            else:
                # Agent network format
                return ReportParser._parse_agent_format(data)

        raise ValueError("Unknown report format")

    @staticmethod
    def _parse_algorithm_format(data: dict) -> List[Finding]:
        """
        Parse algorithm mode format:
        {"target": "...", "findings": [{"type": "...", "location": "0x1000", "confidence": 0.7, "level": "..."}]}
        """
        findings = []
        for i, f in enumerate(data.get("findings", [])):
            # Parse hex address
            loc = f.get("location", "0x0")
            if isinstance(loc, str):
                address = int(loc, 16) if loc.startswith("0x") else int(loc)
            else:
                address = int(loc)

            finding = Finding(
                id=f"algo_{i}_{address:x}",
                address=address,
                vuln_type=f.get("type", "UNKNOWN"),
                confidence=float(f.get("confidence", 0.5)),
                severity=ReportParser._level_to_severity(f.get("level", "Medium")),
            )
            findings.append(finding)

        return findings

    @staticmethod
    def _parse_agent_format(data: dict) -> List[Finding]:
        """
        Parse agent network format:
        {"findings": [{"address": 0x1000, "vuln_type": "...", "severity": "...", "confidence": 0.8, ...}]}
        """
        findings = []
        for i, f in enumerate(data.get("findings", [])):
            # Address can be int or hex string
            addr = f.get("address", 0)
            if isinstance(addr, str):
                address = int(addr, 16) if addr.startswith("0x") else int(addr)
            else:
                address = int(addr)

            finding = Finding(
                id=f"agent_{i}_{address:x}",
                address=address,
                vuln_type=f.get("vuln_type", f.get("type", "UNKNOWN")),
                confidence=float(f.get("confidence", 0.5)),
                severity=f.get("severity", "Medium"),
                sink_api=f.get("sink_api", ""),
                function=f.get("function", ""),
                cwe_id=f.get("cwe_id", ""),
            )
            findings.append(finding)

        return findings

    @staticmethod
    def _level_to_severity(level: str) -> str:
        """Convert confidence level to severity"""
        level_map = {
            "Confirmed": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Suspicious": "Low",
        }
        return level_map.get(level, "Medium")
