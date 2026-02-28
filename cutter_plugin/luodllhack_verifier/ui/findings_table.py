# -*- coding: utf-8 -*-
"""Findings table widget for displaying vulnerability list."""

import cutter
from PySide2.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PySide2.QtCore import Qt, Signal
from PySide2.QtGui import QColor, QBrush

from ..analysis.report_parser import Finding
from typing import List, Optional


class FindingsTableWidget(QTableWidget):
    """Table widget for displaying vulnerability findings"""

    # Signal when finding is selected
    finding_selected = Signal(object)  # Finding

    # Column definitions
    COLUMNS = ["Address", "Type", "Severity", "Confidence", "Status", "AI Verdict"]

    # Severity colors
    SEVERITY_COLORS = {
        "Critical": QColor(255, 100, 100, 150),  # Red
        "High": QColor(255, 180, 100, 150),      # Orange
        "Medium": QColor(255, 255, 100, 150),    # Yellow
        "Low": QColor(200, 255, 200, 150),       # Light green
    }

    # Verdict colors
    VERDICT_COLORS = {
        "true_positive": QColor(255, 100, 100, 150),   # Red
        "false_positive": QColor(100, 255, 100, 150),  # Green
        "inconclusive": QColor(200, 200, 200, 150),    # Gray
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._findings: List[Finding] = []
        self._setup_ui()

    def _setup_ui(self):
        """Setup table UI"""
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)

        # Stretch columns
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Address
        header.setSectionResizeMode(1, QHeaderView.Stretch)           # Type
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Severity
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Confidence
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(5, QHeaderView.Stretch)           # AI Verdict

        # Selection behavior
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAlternatingRowColors(True)

        # Connect signals
        self.cellDoubleClicked.connect(self._on_double_click)
        self.itemSelectionChanged.connect(self._on_selection_changed)

    def load_findings(self, findings: List[Finding]) -> None:
        """Load findings into table"""
        self._findings = findings
        self.setRowCount(0)

        for finding in findings:
            self._add_finding_row(finding)

    def _add_finding_row(self, finding: Finding) -> None:
        """Add a finding to the table"""
        row = self.rowCount()
        self.insertRow(row)

        # Address
        addr_item = QTableWidgetItem(f"0x{finding.address:x}")
        addr_item.setData(Qt.UserRole, finding)  # Store finding reference
        self.setItem(row, 0, addr_item)

        # Type
        type_item = QTableWidgetItem(finding.vuln_type)
        self.setItem(row, 1, type_item)

        # Severity
        sev_item = QTableWidgetItem(finding.severity)
        if finding.severity in self.SEVERITY_COLORS:
            sev_item.setBackground(QBrush(self.SEVERITY_COLORS[finding.severity]))
        self.setItem(row, 2, sev_item)

        # Confidence
        conf_item = QTableWidgetItem(f"{finding.confidence:.0%}")
        self.setItem(row, 3, conf_item)

        # Status
        status_item = QTableWidgetItem(finding.status)
        self.setItem(row, 4, status_item)

        # AI Verdict
        verdict_item = QTableWidgetItem(self._format_verdict(finding))
        if finding.verdict in self.VERDICT_COLORS:
            verdict_item.setBackground(QBrush(self.VERDICT_COLORS[finding.verdict]))
        self.setItem(row, 5, verdict_item)

    def _format_verdict(self, finding: Finding) -> str:
        """Format verdict for display"""
        if not finding.verdict:
            return "-"
        verdict_text = finding.verdict.replace("_", " ").title()
        if finding.verdict_confidence > 0:
            return f"{verdict_text} ({finding.verdict_confidence:.0%})"
        return verdict_text

    def update_finding(self, finding: Finding) -> None:
        """Update a finding in the table"""
        for row in range(self.rowCount()):
            item = self.item(row, 0)
            if item:
                stored = item.data(Qt.UserRole)
                if stored and stored.id == finding.id:
                    # Update status
                    self.item(row, 4).setText(finding.status)
                    # Update verdict
                    verdict_item = self.item(row, 5)
                    verdict_item.setText(self._format_verdict(finding))
                    if finding.verdict in self.VERDICT_COLORS:
                        verdict_item.setBackground(QBrush(self.VERDICT_COLORS[finding.verdict]))
                    break

    def get_selected_finding(self) -> Optional[Finding]:
        """Get currently selected finding"""
        items = self.selectedItems()
        if items:
            row = items[0].row()
            item = self.item(row, 0)
            if item:
                return item.data(Qt.UserRole)
        return None

    def get_all_findings(self) -> List[Finding]:
        """Get all findings"""
        return self._findings

    def _on_double_click(self, row: int, col: int) -> None:
        """Handle double-click to navigate in Cutter"""
        item = self.item(row, 0)
        if item:
            finding = item.data(Qt.UserRole)
            if finding:
                # Navigate to address in Cutter
                cutter.cmd(f"s 0x{finding.address:x}")

    def _on_selection_changed(self) -> None:
        """Handle selection change"""
        finding = self.get_selected_finding()
        if finding:
            self.finding_selected.emit(finding)

    def clear_findings(self) -> None:
        """Clear all findings"""
        self._findings = []
        self.setRowCount(0)
