# -*- coding: utf-8 -*-
"""
luodllhack/analysis/plugins/example_taint_defs.py - Example Taint Definition Plugin

Demonstrates how to extend taint sources and dangerous API definitions via plugins.

Usage:
    1. Place this file in the luodllhack/analysis/plugins/ directory.
    2. TaintEngine will automatically load it during initialization.
    3. The newly defined APIs will be included in the taint analysis.
"""

from .base import TaintDefinitionPlugin


class GameNetworkTaintPlugin(TaintDefinitionPlugin):
    """
    Game Network Protocol Taint Definition Plugin

    Defines common network data input sources and dangerous processing functions for games.
    """

    name = "game_network_taint"
    description = "Game network protocol taint sources and dangerous functions"
    version = "1.0"
    priority = 60

    def get_taint_sources(self):
        """Game-related taint sources"""
        return {
            # Game network APIs
            "RecvGamePacket": {
                "type": "network",
                "tainted_ret": False,
                "tainted_args": [1],  # Second argument is the data buffer
                "description": "Receiving game data packets"
            },
            "ParseNetMessage": {
                "type": "network",
                "tainted_args": [0, 1],
                "description": "Parsing network messages"
            },
            "DecodePacket": {
                "type": "network",
                "tainted_args": [0],
                "tainted_ret": True,
                "description": "Decoding packets"
            },

            # Custom protocol parsing
            "ReadProtobuf": {
                "type": "serialization",
                "tainted_ret": True,
                "description": "Protobuf Deserialization"
            },
            "ParseJSON": {
                "type": "serialization",
                "tainted_ret": True,
                "description": "JSON Parsing"
            },
            "DeserializeData": {
                "type": "serialization",
                "tainted_args": [1],
                "description": "General Deserialization"
            },
        }

    def get_taint_sinks(self):
        """Game-related dangerous functions"""
        return {
            # Game command execution
            "ExecuteGameCommand": {
                "vuln_type": "COMMAND_INJECTION",
                "severity": "critical",
                "sink_args": [0],
                "description": "Executing game commands"
            },
            "RunScript": {
                "vuln_type": "COMMAND_INJECTION",
                "severity": "critical",
                "sink_args": [0],
                "description": "Executing script code"
            },

            # Memory operations
            "CopyPlayerData": {
                "vuln_type": "BUFFER_OVERFLOW",
                "severity": "high",
                "sink_args": [0, 1, 2],
                "description": "Copying player data"
            },
            "WriteInventory": {
                "vuln_type": "BUFFER_OVERFLOW",
                "severity": "high",
                "sink_args": [1],
                "description": "Writing inventory data"
            },

            # Database operations
            "QueryPlayerDB": {
                "vuln_type": "SQL_INJECTION",
                "severity": "high",
                "sink_args": [0],
                "description": "Player database query"
            },
        }


class CryptoTaintPlugin(TaintDefinitionPlugin):
    """
    Cryptography Related Taint Definition Plugin

    Defines input sources for cryptography libraries and potential cryptography misuse.
    """

    name = "crypto_taint"
    description = "Cryptography-related taint sources and dangerous functions"
    version = "1.0"
    priority = 55

    def get_taint_sources(self):
        """Cryptography-related input sources"""
        return {
            # Decryption output
            "CryptDecrypt": {
                "type": "crypto",
                "tainted_args": [3],  # pbData
                "description": "CryptoAPI decryption output"
            },
            "BCryptDecrypt": {
                "type": "crypto",
                "tainted_args": [4],  # pbOutput
                "description": "BCrypt decryption output"
            },
            "EVP_DecryptUpdate": {
                "type": "crypto",
                "tainted_args": [1],  # out
                "description": "OpenSSL decryption output"
            },

            # Key derivation
            "CryptDeriveKey": {
                "type": "crypto",
                "tainted_ret": True,
                "description": "Derived key"
            },
        }

    def get_taint_sinks(self):
        """Cryptography misuse detection"""
        return {
            # Weak cryptography
            "CryptEncrypt": {
                "vuln_type": "WEAK_CRYPTO",
                "severity": "medium",
                "sink_args": [3],
                "description": "Checking for use of weak encryption algorithms"
            },

            # Hardcoded key detection
            "CryptImportKey": {
                "vuln_type": "HARDCODED_KEY",
                "severity": "high",
                "sink_args": [2],
                "description": "Checking if key is hardcoded"
            },
        }
