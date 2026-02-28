# -*- coding: utf-8 -*-
"""Main plugin class for LuoDllHack Verifier."""

import cutter
from PySide2.QtWidgets import QAction, QMenu

from .ui.main_dock import VerifierDockWidget


class LuoDllHackVerifierPlugin(cutter.CutterPlugin):
    """LuoDllHack Verifier - AI-Powered Vulnerability Verification Plugin"""

    name = "LuoDllHack Verifier"
    description = "Verify LuoDllHack vulnerability findings using AI (OpenAI GPT-4)"
    version = "1.0.0"
    author = "LuoDllHack Team"

    def __init__(self):
        super().__init__()
        self.dock = None
        self.main = None

    def setupPlugin(self):
        """Called when plugin is loaded"""
        pass

    def setupInterface(self, main):
        """Setup UI components"""
        self.main = main

        # Create dock widget
        self.dock = VerifierDockWidget(main)

        # Create action for menu
        action = QAction("LuoDllHack Verifier", main)
        action.setCheckable(True)
        action.triggered.connect(self._toggle_dock)

        # Register dock widget
        main.addPluginDockWidget(self.dock, action)

        # Add to Plugins menu
        self._setup_menu(main)

    def _setup_menu(self, main):
        """Setup plugin menu"""
        # Find or create Plugins menu
        plugins_menu = None
        for action in main.menuBar().actions():
            if action.text() == "Plugins":
                plugins_menu = action.menu()
                break

        if plugins_menu is None:
            plugins_menu = main.menuBar().addMenu("Plugins")

        # Create LuoDllHack submenu
        luodllhack_menu = plugins_menu.addMenu("LuoDllHack Verifier")

        # Add actions
        show_action = QAction("Open Panel", main)
        show_action.triggered.connect(lambda: self.dock.show())
        luodllhack_menu.addAction(show_action)

        luodllhack_menu.addSeparator()

        about_action = QAction("About", main)
        about_action.triggered.connect(self._show_about)
        luodllhack_menu.addAction(about_action)

    def _toggle_dock(self, checked):
        """Toggle dock visibility"""
        if checked:
            self.dock.show()
        else:
            self.dock.hide()

    def _show_about(self):
        """Show about dialog"""
        from PySide2.QtWidgets import QMessageBox
        QMessageBox.about(
            self.dock,
            "LuoDllHack Verifier",
            f"""<h3>LuoDllHack Verifier v{self.version}</h3>
            <p>AI-Powered Vulnerability Verification for Cutter</p>
            <p>This plugin uses OpenAI GPT-4 to analyze and verify
            vulnerability findings from LuoDllHack framework.</p>
            <p><b>Features:</b></p>
            <ul>
            <li>Load LuoDllHack JSON vulnerability reports</li>
            <li>Extract context from Cutter (decompilation, CFG, xrefs)</li>
            <li>AI-powered verification with detailed reasoning</li>
            <li>Automatic annotation of verified findings</li>
            </ul>
            <p><b>Usage:</b></p>
            <ol>
            <li>Open target binary in Cutter</li>
            <li>Run LuoDllHack analysis on the binary</li>
            <li>Load the JSON report in this plugin</li>
            <li>Click "Verify" to analyze with AI</li>
            </ol>
            <p>Author: {self.author}</p>
            """
        )

    def terminate(self):
        """Called when plugin is unloaded"""
        if self.dock:
            self.dock.close()
