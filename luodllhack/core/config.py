# -*- coding: utf-8 -*-
"""
luodllhack/core/config.py - Configuration Management

Centralized management of LuoDllHack configuration items.
"""

from dataclasses import dataclass, field
from typing import Optional, List
from pathlib import Path
import os


@dataclass
class VerifyConfidenceConfig:
    """
    Verification module confidence configuration

    Confidence values for different verification methods and vulnerability types.
    """
    # Vulnerability type detection confidence (Direct detection, high confidence)
    double_free_detected: float = 0.95      # Double-Free detected (nearly no false positives)
    uaf_detected: float = 0.88              # Use-After-Free detected
    buffer_overflow_detected: float = 0.85  # Buffer overflow detected
    crash_detected: float = 0.60            # Crash/Exception detected (may be non-security-related)

    # Test trigger confidence (Successfully triggered during active testing)
    double_free_triggered: float = 0.90     # Double-Free triggered
    uaf_triggered: float = 0.85             # UAF triggered
    overflow_triggered: float = 0.75        # Overflow triggered

    # Verification engine confidence (Formal verification)
    unicorn_verified: float = 0.92          # Unicorn emulation confirmed
    z3_satisfiable: float = 0.88            # Z3 constraint satisfiable (trigger path exists)
    z3_unsatisfiable: float = 0.15          # Z3 constraint unsatisfiable (likely false positive)

    # Verification thresholds
    verify_threshold: float = 0.55          # Threshold for verification to pass
    cross_verify_bonus: float = 0.12        # Bonus for cross-verification (confirmed by both static and dynamic analysis)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'double_free_detected': self.double_free_detected,
            'uaf_detected': self.uaf_detected,
            'buffer_overflow_detected': self.buffer_overflow_detected,
            'crash_detected': self.crash_detected,
            'double_free_triggered': self.double_free_triggered,
            'uaf_triggered': self.uaf_triggered,
            'overflow_triggered': self.overflow_triggered,
            'unicorn_verified': self.unicorn_verified,
            'z3_satisfiable': self.z3_satisfiable,
            'z3_unsatisfiable': self.z3_unsatisfiable,
            'verify_threshold': self.verify_threshold,
            'cross_verify_bonus': self.cross_verify_bonus,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'VerifyConfidenceConfig':
        """Create configuration from dictionary"""
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})


@dataclass
class ConfidenceWeightsConfig:
    """
    Confidence scoring weight configuration

    Sum of all factor weights = 1.0, so the total score is within the 0-1 range.
    Weights are optimized based on vulnerability mining experience.
    """
    # === Core Factors (Decisive Evidence) ===
    taint_path_exists: float = 0.28       # Complete taint path exists (most important indicator)
    ai_confirmed: float = 0.15            # AI confirms vulnerability (auxiliary judgment, may be incorrect)
    dangerous_api_call: float = 0.15      # Danger API call (strcpy, sprintf, etc.)

    # === Important Factors (Strongly Correlated Evidence) ===
    no_bounds_check: float = 0.12         # Missing bounds check (key feature of buffer overflow)
    indirect_call_tainted: float = 0.08   # Indirect call controlled by taint (vtable hijacking)
    user_input_direct: float = 0.07       # User input flows directly into dangerous point

    # === Auxiliary Factors (Confidence Enhancement) ===
    cross_function: float = 0.06          # Cross-function propagation confirmed (complex vulnerability feature)
    arithmetic_overflow: float = 0.04     # Potential integer overflow (often leads to heap overflow)
    no_null_check: float = 0.03           # Missing NULL pointer check (UAF auxiliary feature)
    multiple_paths: float = 0.02          # Multiple paths reaching the same sink

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'taint_path_exists': self.taint_path_exists,
            'ai_confirmed': self.ai_confirmed,
            'dangerous_api_call': self.dangerous_api_call,
            'user_input_direct': self.user_input_direct,
            'no_bounds_check': self.no_bounds_check,
            'indirect_call_tainted': self.indirect_call_tainted,
            'arithmetic_overflow': self.arithmetic_overflow,
            'cross_function': self.cross_function,
            'no_null_check': self.no_null_check,
            'multiple_paths': self.multiple_paths,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ConfidenceWeightsConfig':
        """Create configuration from dictionary"""
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})


@dataclass
class LuoDllHackConfig:
    """LuoDllHack configuration"""

    # ==========================================================================
    # Analysis Configuration
    # ==========================================================================

    # Taint Analysis
    taint_max_depth: int = 3000            # Maximum analysis depth (number of instructions)
    taint_cross_function: bool = True      # Enable cross-function analysis
    taint_track_memory: bool = True        # Track memory locations

    # Symbolic Execution
    symbolic_timeout: int = 600            # Timeout (seconds)
    symbolic_max_states: int = 500         # Maximum number of states (prevent state explosion)
    symbolic_solve_constraints: bool = True # Solve constraints

    # Memory Analysis
    memory_track_lifecycle: bool = True    # Track pointer lifecycle
    memory_detect_uaf: bool = True         # Detect UAF
    memory_detect_double_free: bool = True # Detect Double-Free

    # ==========================================================================
    # Fuzzing Configuration
    # ==========================================================================

    fuzz_enable: bool = True               # Enable fuzzing
    fuzz_iterations: int = 500             # Iterations for internal fuzzer
    fuzz_timeout: int = 5                  # Timeout per test (seconds)

    # External Fuzzer Configuration (WinAFL/AFL/LibFuzzer)
    fuzz_external_enable: bool = False     # Enable external fuzzer integration
    fuzz_external_type: str = "winafl"     # External fuzzer type: winafl | afl | libfuzzer
    fuzz_external_timeout: int = 60        # Running time for external fuzzer (minutes)
    fuzz_winafl_path: Optional[str] = None # WinAFL path (or use WINAFL_PATH environment variable)
    fuzz_dynamorio_path: Optional[str] = None  # DynamoRIO path (or use DYNAMORIO_PATH environment variable)
    fuzz_afl_path: Optional[str] = None    # AFL/AFL++ path (or use AFL_PATH environment variable)
    fuzz_generate_harness: bool = True     # Automatically generate fuzzing harness
    fuzz_seeds_dir: Optional[Path] = None  # Directory for seed files
    fuzz_output_dir: Optional[Path] = None # Directory for fuzzing output

    # ==========================================================================
    # Verification Configuration
    # ==========================================================================

    # Dynamic Verification
    verify_enable_dynamic: bool = True     # Enable Speakeasy dynamic verification
    verify_emulation_timeout: int = 60     # Emulation timeout (seconds)

    # Confidence Scoring
    confidence_ai_weight: float = 0.15     # Weight for AI confirmation (deprecated, use confidence_weights)
    confidence_min_threshold: float = 0.45 # Minimum confidence threshold
    confidence_weights: ConfidenceWeightsConfig = field(default_factory=ConfidenceWeightsConfig)
    verify_confidence: VerifyConfidenceConfig = field(default_factory=VerifyConfidenceConfig)

    # ==========================================================================
    # AI Configuration
    # ==========================================================================

    ai_api_key: Optional[str] = None       # Gemini API Key
    ai_model: str = "gemini-2.5-flash"     # Model name
    ai_max_tokens: int = 8192              # Maximum number of tokens
    ai_temperature: float = 0.05           # Temperature (low values for more deterministic output)

    # ==========================================================================
    # Multi-Agent Configuration
    # ==========================================================================

    ai_multi_agent: bool = False           # Enable multi-agent collaboration mode
    ai_multi_agent_workers: int = 4        # Number of parallel worker threads
    ai_agent_pool_size: int = 3            # LLM client pool size
    ai_agent_task_timeout: int = 120       # Timeout for single task (seconds)
    ai_agent_max_concurrent: int = 3       # Max concurrent tasks per agent

    # ==========================================================================
    # Multi-LLM Backend Configuration
    # ==========================================================================

    ai_backend: str = "gemini"             # LLM backend: gemini | openai | ollama | anthropic

    # OpenAI Configuration
    ai_openai_api_key: Optional[str] = None
    ai_openai_model: str = "gpt-4"
    ai_openai_base_url: Optional[str] = None  # Optional, for proxy or Azure

    # Ollama Configuration (Local Models)
    ai_ollama_base_url: str = "http://localhost:11434"
    ai_ollama_model: str = "llama3"

    # Anthropic Configuration
    ai_anthropic_api_key: Optional[str] = None
    ai_anthropic_model: str = "claude-3-opus-20240229"

    # ==========================================================================
    # Output Configuration
    # ==========================================================================

    output_dir: Path = field(default_factory=lambda: Path.cwd())
    output_report: bool = True             # Generate analysis report

    # ==========================================================================
    # Logging Configuration
    # ==========================================================================

    log_level: str = "INFO"
    log_file: Optional[Path] = None

    def __post_init__(self):
        # Apply environment variable overrides
        self._apply_env_overrides()

        # Ensure output directory type is correct
        if not isinstance(self.output_dir, Path):
            self.output_dir = Path(self.output_dir)

    def _apply_env_overrides(self):
        """
        Read configuration overrides from environment variables.

        Environment variable naming rule: LUODLLHACK_<FIELD_NAME>
        Example:
            - LUODLLHACK_TAINT_MAX_DEPTH=2000
            - LUODLLHACK_AI_MODEL=gemini-1.5-pro
            - LUODLLHACK_LOG_LEVEL=DEBUG
            - GEMINI_API_KEY=xxx (Compatible with old format)
        """
        # Special handling for API Key (Compatible with old format)
        if self.ai_api_key is None:
            self.ai_api_key = os.environ.get("LUODLLHACK_AI_API_KEY") or os.environ.get("GEMINI_API_KEY")

        # Define overridable fields and their type converters
        overridable = {
            # Analysis Configuration
            'taint_max_depth': int,
            'taint_cross_function': self._parse_bool,
            'taint_track_memory': self._parse_bool,
            # Symbolic Execution
            'symbolic_timeout': int,
            'symbolic_max_states': int,
            'symbolic_solve_constraints': self._parse_bool,
            # Memory Analysis
            'memory_track_lifecycle': self._parse_bool,
            'memory_detect_uaf': self._parse_bool,
            'memory_detect_double_free': self._parse_bool,
            # Fuzzing Configuration
            'fuzz_enable': self._parse_bool,
            'fuzz_iterations': int,
            'fuzz_timeout': int,
            'fuzz_external_enable': self._parse_bool,
            'fuzz_external_type': str,
            'fuzz_external_timeout': int,
            'fuzz_winafl_path': str,
            'fuzz_dynamorio_path': str,
            'fuzz_afl_path': str,
            'fuzz_generate_harness': self._parse_bool,
            'fuzz_seeds_dir': self._parse_path,
            'fuzz_output_dir': self._parse_path,
            # Verification Configuration
            'verify_enable_dynamic': self._parse_bool,
            'verify_emulation_timeout': int,
            # Confidence
            'confidence_min_threshold': float,
            # AI Configuration
            'ai_model': str,
            'ai_max_tokens': int,
            'ai_temperature': float,
            # Multi-Agent Configuration
            'ai_multi_agent': self._parse_bool,
            'ai_multi_agent_workers': int,
            'ai_agent_pool_size': int,
            'ai_agent_task_timeout': int,
            'ai_agent_max_concurrent': int,
            # Multi-LLM Backend Configuration
            'ai_backend': str,
            'ai_openai_model': str,
            'ai_openai_base_url': str,
            'ai_ollama_base_url': str,
            'ai_ollama_model': str,
            'ai_anthropic_model': str,
            # Output Configuration
            'output_dir': Path,
            'output_report': self._parse_bool,
            # Logging
            'log_level': str,
            'log_file': self._parse_path,
        }

        # Additional API Key environment variables
        if self.ai_openai_api_key is None:
            self.ai_openai_api_key = os.environ.get("LUODLLHACK_AI_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if self.ai_anthropic_api_key is None:
            self.ai_anthropic_api_key = os.environ.get("LUODLLHACK_AI_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")

        for field, converter in overridable.items():
            env_name = f"LUODLLHACK_{field.upper()}"
            env_value = os.environ.get(env_name)
            if env_value is not None:
                try:
                    converted = converter(env_value)
                    setattr(self, field, converted)
                except (ValueError, TypeError):
                    # Silently ignore invalid values, keeping defaults
                    pass

    @staticmethod
    def _parse_bool(value: str) -> bool:
        """Parse boolean environment variables"""
        return value.lower() in ('true', '1', 'yes', 'on')

    @staticmethod
    def _parse_path(value: str) -> Optional[Path]:
        """Parse path environment variables"""
        if not value or value.lower() in ('none', 'null', ''):
            return None
        return Path(value)

    @classmethod
    def from_dict(cls, data: dict) -> 'LuoDllHackConfig':
        """Create configuration from dictionary"""
        data = data.copy()
        # Handle nested confidence_weights
        if 'confidence_weights' in data and isinstance(data['confidence_weights'], dict):
            data['confidence_weights'] = ConfidenceWeightsConfig.from_dict(data['confidence_weights'])
        # Handle nested verify_confidence
        if 'verify_confidence' in data and isinstance(data['verify_confidence'], dict):
            data['verify_confidence'] = VerifyConfidenceConfig.from_dict(data['verify_confidence'])
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})

    @classmethod
    def from_yaml(cls, path: str) -> 'LuoDllHackConfig':
        """Load configuration from a YAML file"""
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            return cls.from_dict(data or {})
        except ImportError:
            raise ImportError("PyYAML required: pip install pyyaml")
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {path}")

    def to_dict(self) -> dict:
        """Convert to complete dictionary"""
        return {
            # Analysis Configuration
            'taint_max_depth': self.taint_max_depth,
            'taint_cross_function': self.taint_cross_function,
            'taint_track_memory': self.taint_track_memory,
            # Symbolic Execution
            'symbolic_timeout': self.symbolic_timeout,
            'symbolic_max_states': self.symbolic_max_states,
            'symbolic_solve_constraints': self.symbolic_solve_constraints,
            # Memory Analysis
            'memory_track_lifecycle': self.memory_track_lifecycle,
            'memory_detect_uaf': self.memory_detect_uaf,
            'memory_detect_double_free': self.memory_detect_double_free,
            # Fuzzing Configuration
            'fuzz_enable': self.fuzz_enable,
            'fuzz_iterations': self.fuzz_iterations,
            'fuzz_timeout': self.fuzz_timeout,
            'fuzz_external_enable': self.fuzz_external_enable,
            'fuzz_external_type': self.fuzz_external_type,
            'fuzz_external_timeout': self.fuzz_external_timeout,
            'fuzz_winafl_path': self.fuzz_winafl_path,
            'fuzz_dynamorio_path': self.fuzz_dynamorio_path,
            'fuzz_afl_path': self.fuzz_afl_path,
            'fuzz_generate_harness': self.fuzz_generate_harness,
            'fuzz_seeds_dir': str(self.fuzz_seeds_dir) if self.fuzz_seeds_dir else None,
            'fuzz_output_dir': str(self.fuzz_output_dir) if self.fuzz_output_dir else None,
            # Verification Configuration
            'verify_enable_dynamic': self.verify_enable_dynamic,
            'verify_emulation_timeout': self.verify_emulation_timeout,
            # Confidence
            'confidence_min_threshold': self.confidence_min_threshold,
            'confidence_weights': self.confidence_weights.to_dict(),
            'verify_confidence': self.verify_confidence.to_dict(),
            # AI Configuration
            'ai_model': self.ai_model,
            'ai_max_tokens': self.ai_max_tokens,
            'ai_temperature': self.ai_temperature,
            # Multi-Agent Configuration
            'ai_multi_agent': self.ai_multi_agent,
            'ai_multi_agent_workers': self.ai_multi_agent_workers,
            'ai_agent_pool_size': self.ai_agent_pool_size,
            'ai_agent_task_timeout': self.ai_agent_task_timeout,
            'ai_agent_max_concurrent': self.ai_agent_max_concurrent,
            # Multi-LLM Backend Configuration
            'ai_backend': self.ai_backend,
            'ai_openai_model': self.ai_openai_model,
            'ai_openai_base_url': self.ai_openai_base_url,
            'ai_ollama_base_url': self.ai_ollama_base_url,
            'ai_ollama_model': self.ai_ollama_model,
            'ai_anthropic_model': self.ai_anthropic_model,
            # Output Configuration
            'output_dir': str(self.output_dir),
            'output_report': self.output_report,
            # Logging
            'log_level': self.log_level,
            'log_file': str(self.log_file) if self.log_file else None,
        }

    def to_yaml(self, path: str) -> None:
        """Save configuration to a YAML file"""
        try:
            import yaml
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(self.to_dict(), f, default_flow_style=False, allow_unicode=True)
        except ImportError:
            raise ImportError("PyYAML required: pip install pyyaml")

    def validate(self) -> List[str]:
        """
        Validate the configuration for correctness.

        Returns:
            List of error messages (Empty list if valid)
        """
        errors = []

        # Analysis configuration validation
        if self.taint_max_depth < 100:
            errors.append(f"taint_max_depth ({self.taint_max_depth}) is too small, recommended >= 100")
        if self.taint_max_depth > 100000:
            errors.append(f"taint_max_depth ({self.taint_max_depth}) is too large, may cause performance issues")

        # Symbolic execution validation
        if self.symbolic_timeout < 10:
            errors.append(f"symbolic_timeout ({self.symbolic_timeout}s) is too short")
        if self.symbolic_max_states < 10:
            errors.append(f"symbolic_max_states ({self.symbolic_max_states}) is too small")

        # Confidence validation
        if not 0.0 <= self.confidence_min_threshold <= 1.0:
            errors.append(f"confidence_min_threshold ({self.confidence_min_threshold}) must be between 0 and 1")

        # AI configuration validation
        if self.ai_max_tokens < 100:
            errors.append(f"ai_max_tokens ({self.ai_max_tokens}) is too small")
        if not 0.0 <= self.ai_temperature <= 2.0:
            errors.append(f"ai_temperature ({self.ai_temperature}) recommended range is 0-2")

        # Logging level validation
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.log_level.upper() not in valid_log_levels:
            errors.append(f"log_level ({self.log_level}) is invalid, should be one of: {valid_log_levels}")

        return errors


# Global default configuration instance - automatically finds configuration file
def _load_default_config() -> LuoDllHackConfig:
    """Automatically load the default configuration file"""
    import os
    # Locations to search for the configuration file
    search_paths = [
        "luodllhack.yaml",
        ".luodllhack.yaml",
        os.path.expanduser("~/.luodllhack.yaml"),
        os.path.expanduser("~/luodllhack.yaml"),
    ]
    for path in search_paths:
        if os.path.exists(path):
            try:
                config = LuoDllHackConfig.from_yaml(path)
                print(f"[*] Loaded config from: {path}")
                return config
            except Exception as e:
                print(f"[!] Failed to load config from {path}: {e}")
    return LuoDllHackConfig()

default_config = _load_default_config()


def load_config(path: Optional[str] = None) -> LuoDllHackConfig:
    """
    Load configuration (supports YAML and environment variables).

    Args:
        path: Configuration file path (optional)

    Returns:
        Configuration instance
    """
    if path:
        return LuoDllHackConfig.from_yaml(path)
    return LuoDllHackConfig()
