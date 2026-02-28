# -*- coding: utf-8 -*-
"""
LuoDllHack Verifier - Cutter Plugin for AI-Powered Vulnerability Verification

Standalone plugin using OpenAI GPT-4 to verify LuoDllHack vulnerability findings.

Installation:
    Copy this directory to:
    - Windows: %APPDATA%/rizin/cutter/plugins/python/
    - Linux: ~/.local/share/rizin/cutter/plugins/python/
"""

from .plugin import LuoDllHackVerifierPlugin


def create_cutter_plugin():
    """Cutter plugin entry point"""
    return LuoDllHackVerifierPlugin()


__version__ = "1.0.0"
__author__ = "LuoDllHack Team"
