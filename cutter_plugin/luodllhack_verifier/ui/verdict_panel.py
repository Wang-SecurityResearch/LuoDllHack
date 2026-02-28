# -*- coding: utf-8 -*-
"""Verdict panel for displaying AI verification results."""

from PySide2.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QGroupBox, QFrame, QSplitter
)
from PySide2.QtCore import Qt
from PySide2.QtGui import QFont

from ..analysis.report_parser import Finding
from ..analysis.context_extractor import VerificationContext
from ..ai.openai_client import VerificationResult


class VerdictPanel(QWidget):
    """Panel for displaying verification context and AI verdict"""

    VERDICT_STYLES = {
        "true_positive": "background-color: #ffcccc; color: #cc0000; font-weight: bold;",
        "false_positive": "background-color: #ccffcc; color: #006600; font-weight: bold;",
        "inconclusive": "background-color: #eeeeee; color: #666666; font-weight: bold;",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        """Setup panel UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Splitter for code and verdict
        splitter = QSplitter(Qt.Vertical)

        # Code context group
        code_group = QGroupBox("Code Context")
        code_layout = QVBoxLayout(code_group)

        self.code_text = QTextEdit()
        self.code_text.setReadOnly(True)
        self.code_text.setFont(QFont("Consolas", 9))
        self.code_text.setPlaceholderText("Select a finding to view decompiled code...")
        code_layout.addWidget(self.code_text)

        splitter.addWidget(code_group)

        # Verdict group
        verdict_group = QGroupBox("AI Verification Result")
        verdict_layout = QVBoxLayout(verdict_group)

        # Verdict header
        self.verdict_label = QLabel("No verification yet")
        self.verdict_label.setAlignment(Qt.AlignCenter)
        self.verdict_label.setStyleSheet("padding: 10px; font-size: 14px;")
        verdict_layout.addWidget(self.verdict_label)

        # Verdict details
        self.verdict_text = QTextEdit()
        self.verdict_text.setReadOnly(True)
        self.verdict_text.setPlaceholderText("AI analysis results will appear here...")
        verdict_layout.addWidget(self.verdict_text)

        splitter.addWidget(verdict_group)

        # Set splitter sizes
        splitter.setSizes([300, 200])

        layout.addWidget(splitter)

    def show_context(self, finding: Finding, context: VerificationContext) -> None:
        """Show code context for a finding"""
        # Build code display
        code_parts = []

        # Function header
        code_parts.append(f"// Function: {context.function_name}")
        code_parts.append(f"// Address: 0x{finding.address:x}")
        code_parts.append(f"// Vulnerability: {finding.vuln_type}")
        if finding.sink_api:
            code_parts.append(f"// Sink API: {finding.sink_api}")
        code_parts.append("")

        # Decompiled code
        if context.decompiled:
            code_parts.append("/* Decompiled Code */")
            code_parts.append(context.decompiled)
        elif context.disassembly:
            code_parts.append("; Disassembly")
            code_parts.append(context.disassembly)
        else:
            code_parts.append("// No code available")

        self.code_text.setText("\n".join(code_parts))

        # Clear previous verdict
        self.verdict_label.setText("Pending verification...")
        self.verdict_label.setStyleSheet("padding: 10px; font-size: 14px;")
        self.verdict_text.clear()

    def show_verifying(self, finding_id: str, message: str) -> None:
        """Show verification in progress"""
        self.verdict_label.setText(f"Verifying... {message}")
        self.verdict_label.setStyleSheet("padding: 10px; font-size: 14px; color: #666;")

    def show_result(self, result: VerificationResult) -> None:
        """Show verification result"""
        if not result.success:
            self.verdict_label.setText(f"Error: {result.error}")
            self.verdict_label.setStyleSheet("padding: 10px; font-size: 14px; color: red;")
            return

        # Verdict header
        verdict_text = result.verdict.replace("_", " ").upper()
        style = self.VERDICT_STYLES.get(result.verdict, "")
        self.verdict_label.setText(f"{verdict_text} (Confidence: {result.confidence:.0%})")
        self.verdict_label.setStyleSheet(f"padding: 10px; font-size: 14px; {style}")

        # Build details text
        details = []

        # Exploitability
        if result.exploitability:
            details.append(f"Exploitability: {result.exploitability.upper()}")
            details.append("")

        # Reasoning
        details.append("REASONING:")
        details.append(result.reasoning)
        details.append("")

        # Key evidence
        if result.key_evidence:
            details.append("KEY EVIDENCE:")
            for evidence in result.key_evidence:
                details.append(f"  - {evidence}")
            details.append("")

        # Mitigations
        if result.mitigations_found:
            details.append("MITIGATIONS FOUND:")
            for mitigation in result.mitigations_found:
                details.append(f"  - {mitigation}")

        self.verdict_text.setText("\n".join(details))

    def show_error(self, error: str) -> None:
        """Show error message"""
        self.verdict_label.setText("Error")
        self.verdict_label.setStyleSheet("padding: 10px; font-size: 14px; color: red;")
        self.verdict_text.setText(f"Verification failed:\n\n{error}")

    def clear(self) -> None:
        """Clear panel"""
        self.code_text.clear()
        self.verdict_label.setText("No verification yet")
        self.verdict_label.setStyleSheet("padding: 10px; font-size: 14px;")
        self.verdict_text.clear()
