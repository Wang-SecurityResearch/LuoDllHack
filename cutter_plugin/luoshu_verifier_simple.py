# -*- coding: utf-8 -*-
"""
LuoDllHack Verifier - Simple Version for Testing
"""

import cutter
from PySide2.QtWidgets import (
    QAction, QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox
)
from PySide2.QtCore import Qt


class LuoDllHackVerifierDock(cutter.CutterDockWidget):
    """Simple test dock"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("LuoDllHackVerifierTest")
        self.setWindowTitle("LuoDllHack Verifier")

        widget = QWidget()
        layout = QVBoxLayout(widget)

        label = QLabel("LuoDllHack Verifier Plugin Loaded!")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        btn = QPushButton("Test Button")
        btn.clicked.connect(lambda: QMessageBox.information(self, "Test", "It works!"))
        layout.addWidget(btn)

        self.setWidget(widget)


class LuoDllHackVerifierPlugin(cutter.CutterPlugin):
    """LuoDllHack Verifier Plugin"""

    name = "LuoDllHack Verifier"
    description = "AI-Powered Vulnerability Verification"
    version = "1.0.0"
    author = "LuoDllHack Team"

    def __init__(self):
        super().__init__()
        self.dock = None

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        self.dock = LuoDllHackVerifierDock(main)
        action = QAction("LuoDllHack Verifier", main)
        action.setCheckable(True)
        main.addPluginDockWidget(self.dock, action)

    def terminate(self):
        pass


def create_cutter_plugin():
    return LuoDllHackVerifierPlugin()
