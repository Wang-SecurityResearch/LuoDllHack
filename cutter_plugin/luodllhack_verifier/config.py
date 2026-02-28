# -*- coding: utf-8 -*-
"""Configuration management for LuoDllHack Verifier plugin."""

import os
import json
from pathlib import Path
from typing import Optional


class PluginConfig:
    """Plugin configuration manager (Singleton)"""

    CONFIG_DIR = Path.home() / ".cutter"
    CONFIG_FILE = CONFIG_DIR / "luodllhack_verifier.json"

    DEFAULTS = {
        "api_key": "",
        "model": "gpt-4",
        "max_tokens": 4096,
        "temperature": 0.1,
    }

    _instance: Optional['PluginConfig'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._config = self.DEFAULTS.copy()
        self.load()

    def load(self) -> None:
        """Load configuration from file"""
        if self.CONFIG_FILE.exists():
            try:
                with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                    self._config.update(json.load(f))
            except Exception:
                pass

    def save(self) -> None:
        """Save configuration to file"""
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(self._config, f, indent=2)

    @property
    def api_key(self) -> str:
        """Get API key (env var takes precedence)"""
        return os.environ.get("OPENAI_API_KEY", self._config.get("api_key", ""))

    @api_key.setter
    def api_key(self, value: str) -> None:
        self._config["api_key"] = value
        self.save()

    @property
    def model(self) -> str:
        return self._config.get("model", "gpt-4")

    @model.setter
    def model(self, value: str) -> None:
        self._config["model"] = value
        self.save()

    @property
    def max_tokens(self) -> int:
        return self._config.get("max_tokens", 4096)

    @property
    def temperature(self) -> float:
        return self._config.get("temperature", 0.1)

    def has_api_key(self) -> bool:
        return bool(self.api_key)


config = PluginConfig()
