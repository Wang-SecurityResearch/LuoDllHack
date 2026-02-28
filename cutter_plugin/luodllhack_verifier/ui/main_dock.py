# -*- coding: utf-8 -*-
"""Main dock widget for LuoDllHack Verifier."""

import cutter
from PySide2.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QFileDialog, QMessageBox, QGroupBox, QSplitter,
    QProgressBar, QInputDialog
)
from PySide2.QtCore import Qt

from ..config import config
from ..analysis.report_parser import ReportParser, Finding
from ..analysis.context_extractor import ContextExtractor
from ..analysis.vuln_checkers import VulnChecker
from ..ai.openai_client import OpenAIVerifier, VerificationRequest, VerificationResult
from .findings_table import FindingsTableWidget
from .verdict_panel import VerdictPanel

from typing import List, Optional


class VerifierDockWidget(cutter.CutterDockWidget):
    """Main dock widget for LuoDllHack Verifier"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("LuoDllHackVerifier")
        self.setWindowTitle("LuoDllHack Verifier")

        self._findings: List[Finding] = []
        self._context_extractor = ContextExtractor()
        self._vuln_checker = VulnChecker()
        self._verifier: Optional[OpenAIVerifier] = None
        self._current_context = None

        self._setup_ui()

    def _setup_ui(self):
        """Setup dock UI"""
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)

        # === Report Loading Section ===
        load_group = QGroupBox("Load Report")
        load_layout = QHBoxLayout(load_group)

        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("LuoDllHack report JSON file...")
        load_layout.addWidget(self.path_edit)

        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_report)
        load_layout.addWidget(browse_btn)

        load_btn = QPushButton("Load")
        load_btn.clicked.connect(self._load_report)
        load_layout.addWidget(load_btn)

        layout.addWidget(load_group)

        # === Main Splitter ===
        splitter = QSplitter(Qt.Vertical)

        # Findings table
        table_group = QGroupBox("Findings")
        table_layout = QVBoxLayout(table_group)

        self.findings_table = FindingsTableWidget()
        self.findings_table.finding_selected.connect(self._on_finding_selected)
        table_layout.addWidget(self.findings_table)

        # Control buttons
        btn_layout = QHBoxLayout()

        self.verify_btn = QPushButton("Verify Selected")
        self.verify_btn.clicked.connect(self._verify_selected)
        self.verify_btn.setEnabled(False)
        btn_layout.addWidget(self.verify_btn)

        self.verify_all_btn = QPushButton("Verify All")
        self.verify_all_btn.clicked.connect(self._verify_all)
        self.verify_all_btn.setEnabled(False)
        btn_layout.addWidget(self.verify_all_btn)

        btn_layout.addStretch()

        self.api_key_btn = QPushButton("API Key")
        self.api_key_btn.clicked.connect(self._configure_api_key)
        btn_layout.addWidget(self.api_key_btn)

        table_layout.addLayout(btn_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        table_layout.addWidget(self.progress_bar)

        splitter.addWidget(table_group)

        # Verdict panel
        self.verdict_panel = VerdictPanel()
        splitter.addWidget(self.verdict_panel)

        splitter.setSizes([250, 350])
        layout.addWidget(splitter)

        # Status label
        self.status_label = QLabel("Ready. Load a LuoDllHack report to begin.")
        layout.addWidget(self.status_label)

        self.setWidget(main_widget)

    def _browse_report(self):
        """Browse for report file"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select LuoDllHack Report",
            "", "JSON Files (*.json);;All Files (*)"
        )
        if path:
            self.path_edit.setText(path)

    def _load_report(self):
        """Load report from file"""
        path = self.path_edit.text().strip()
        if not path:
            QMessageBox.warning(self, "Error", "Please select a report file.")
            return

        try:
            self._findings = ReportParser.load(path)
            self.findings_table.load_findings(self._findings)
            self.verify_btn.setEnabled(True)
            self.verify_all_btn.setEnabled(True)
            self.status_label.setText(f"Loaded {len(self._findings)} findings from report.")
            self.verdict_panel.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load report:\n{e}")

    def _on_finding_selected(self, finding: Finding):
        """Handle finding selection"""
        try:
            # Extract context from Cutter
            self._current_context = self._context_extractor.extract(finding.address)
            self.verdict_panel.show_context(finding, self._current_context)

            # Show existing verdict if available
            if finding.verdict:
                self.verdict_panel.show_result(VerificationResult(
                    finding_id=finding.id,
                    success=True,
                    verdict=finding.verdict,
                    confidence=finding.verdict_confidence,
                    reasoning=finding.verdict_reasoning
                ))
        except Exception as e:
            self.status_label.setText(f"Error extracting context: {e}")

    def _verify_selected(self):
        """Verify selected finding"""
        finding = self.findings_table.get_selected_finding()
        if not finding:
            QMessageBox.warning(self, "Error", "Please select a finding to verify.")
            return

        if not config.has_api_key():
            QMessageBox.warning(self, "Error", "Please configure your OpenAI API key first.")
            self._configure_api_key()
            return

        self._start_verification([finding])

    def _verify_all(self):
        """Verify all findings"""
        if not self._findings:
            return

        if not config.has_api_key():
            QMessageBox.warning(self, "Error", "Please configure your OpenAI API key first.")
            self._configure_api_key()
            return

        # Filter unverified findings
        unverified = [f for f in self._findings if f.status == "pending"]
        if not unverified:
            QMessageBox.information(self, "Info", "All findings have already been verified.")
            return

        self._start_verification(unverified)

    def _start_verification(self, findings: List[Finding]):
        """Start verification for given findings"""
        # Create verifier if needed
        if self._verifier is None:
            self._verifier = OpenAIVerifier()
            self._verifier.result_ready.connect(self._on_verification_result)
            self._verifier.progress_update.connect(self._on_verification_progress)
            self._verifier.error_occurred.connect(self._on_verification_error)
            self._verifier.start()

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(len(findings))
        self.progress_bar.setValue(0)
        self.verify_btn.setEnabled(False)
        self.verify_all_btn.setEnabled(False)

        # Queue verification requests
        for finding in findings:
            finding.status = "verifying"
            self.findings_table.update_finding(finding)

            # Extract context
            context = self._context_extractor.extract(finding.address)

            # Run static analysis
            analysis = self._vuln_checker.analyze(context, finding.vuln_type, finding.sink_api)

            # Queue request
            request = VerificationRequest(
                finding_id=finding.id,
                finding=finding,
                context=context,
                analysis=analysis
            )
            self._verifier.queue_request(request)

        self.status_label.setText(f"Verifying {len(findings)} findings...")

    def _on_verification_result(self, result: VerificationResult):
        """Handle verification result"""
        # Find and update finding
        for finding in self._findings:
            if finding.id == result.finding_id:
                finding.status = "verified"
                finding.verdict = result.verdict
                finding.verdict_confidence = result.confidence
                finding.verdict_reasoning = result.reasoning
                self.findings_table.update_finding(finding)

                # Add comment in Cutter
                verdict_short = result.verdict.replace("_", " ").upper()
                cutter.cmd(f'CC "[Verifier] {verdict_short} ({result.confidence:.0%})" @ 0x{finding.address:x}')
                break

        # Update progress
        verified_count = sum(1 for f in self._findings if f.status == "verified")
        self.progress_bar.setValue(verified_count)

        # Show result if this is the selected finding
        selected = self.findings_table.get_selected_finding()
        if selected and selected.id == result.finding_id:
            self.verdict_panel.show_result(result)

        # Check if all done
        pending = sum(1 for f in self._findings if f.status == "verifying")
        if pending == 0:
            self._verification_complete()

    def _on_verification_progress(self, finding_id: str, message: str):
        """Handle progress update"""
        self.status_label.setText(f"Verifying 0x{finding_id.split('_')[-1]}: {message}")
        self.verdict_panel.show_verifying(finding_id, message)

    def _on_verification_error(self, finding_id: str, error: str):
        """Handle verification error"""
        self.status_label.setText(f"Error: {error}")

        # Update finding status
        for finding in self._findings:
            if finding.id == finding_id:
                finding.status = "error"
                self.findings_table.update_finding(finding)
                break

    def _verification_complete(self):
        """Handle verification completion"""
        self.progress_bar.setVisible(False)
        self.verify_btn.setEnabled(True)
        self.verify_all_btn.setEnabled(True)

        # Count results
        tp_count = sum(1 for f in self._findings if f.verdict == "true_positive")
        fp_count = sum(1 for f in self._findings if f.verdict == "false_positive")
        inc_count = sum(1 for f in self._findings if f.verdict == "inconclusive")

        self.status_label.setText(
            f"Verification complete. TP: {tp_count}, FP: {fp_count}, Inconclusive: {inc_count}"
        )

    def _configure_api_key(self):
        """Configure OpenAI API key"""
        current = config.api_key
        masked = "*" * (len(current) - 4) + current[-4:] if len(current) > 4 else current

        key, ok = QInputDialog.getText(
            self, "OpenAI API Key",
            "Enter your OpenAI API key:\n(or set OPENAI_API_KEY environment variable)",
            text=masked if current else ""
        )

        if ok and key and not key.startswith("*"):
            config.api_key = key
            QMessageBox.information(self, "Success", "API key saved.")

    def closeEvent(self, event):
        """Handle dock close"""
        if self._verifier:
            self._verifier.stop()
        super().closeEvent(event)
