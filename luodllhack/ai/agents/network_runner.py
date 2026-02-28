# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/network_runner.py
Network Runner - Manages the startup and execution of the Agent network

Provides:
    - Agent network initialization
    - Task dispatching
    - Result collection
    - Backward compatibility with Orchestrator interface
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional, TYPE_CHECKING

from .base import (
    AgentCapability,
    TaskAssignment,
    AgentResult,
)
from .message_bus import MessageBus
from .shared_state import SharedState, AnalysisContext
from .registry import AgentRegistry
from .network_agent import NetworkAgent

if TYPE_CHECKING:
    from .llm_pool import LLMClientPool
    from luodllhack.core.config import LuoDllHackConfig

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class NetworkConfig:
    """Network configuration"""
    # Agent Configuration
    enable_analyzer: bool = True
    enable_verifier: bool = True
    enable_exploiter: bool = True
    enable_validator: bool = True
    enable_critic: bool = True

    # Run configuration
    max_concurrent_tasks: int = 5
    task_timeout: float = 300.0
    heartbeat_interval: float = 30.0

    # LLM Configuration
    llm_backend: str = "gemini"
    llm_api_key: Optional[str] = None

    # Analysis configuration
    max_react_iterations: int = 15
    auto_delegate: bool = True

    @classmethod
    def from_luodllhack_config(cls, config: "LuoDllHackConfig") -> "NetworkConfig":
        """Create from LuoDllHack configuration"""
        return cls(
            llm_backend=getattr(config, 'ai_backend', 'gemini'),
            llm_api_key=getattr(config, 'ai_api_key', None),
            max_react_iterations=getattr(config, 'ai_agent_task_timeout', 120) // 8,  # approx 15 iterations
            task_timeout=float(getattr(config, 'ai_agent_task_timeout', 120)),
            max_concurrent_tasks=getattr(config, 'ai_agent_max_concurrent', 3),
        )


# =============================================================================
# NetworkRunner
# =============================================================================

class NetworkRunner:
    """
    Agent Network Runner

    Manages the decentralized Agent network:
    - Initialize all Agents
    - Register to AgentRegistry
    - Start MessageBus
    - Dispatch initial tasks
    - Collect results

    Usage example:
        runner = NetworkRunner(binary_path, config)
        runner.start()

        # Dispatch tasks
        results = runner.run_analysis()

        runner.stop()
    """

    def __init__(
        self,
        binary_path: Path,
        config: Optional[NetworkConfig] = None,
        llm_pool: Optional["LLMClientPool"] = None,
    ):
        """
        Initialize network runner

        Args:
            binary_path: Target binary file path
            config: Network configuration
            llm_pool: LLM client pool
        """
        self.binary_path = Path(binary_path)
        self.config = config or NetworkConfig()
        self.llm_pool = llm_pool

        # Core components
        self.message_bus = MessageBus()
        self.shared_state = SharedState()
        self.registry = AgentRegistry(self.message_bus)

        # Agent instances
        self._agents: Dict[str, NetworkAgent] = {}

        # Tool registry (shared)
        self._tool_registry = None

        # Run state
        self._running = False
        self._start_time: Optional[float] = None

        # Result collection
        self._results: List[AgentResult] = []
        self._all_findings: List[Dict[str, Any]] = []

        logger.info(f"NetworkRunner initialized for {binary_path}")

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def start(self) -> None:
        """Start network"""
        if self._running:
            logger.warning("NetworkRunner is already running")
            return

        logger.info("Starting Agent Network...")
        self._start_time = time.time()

        # 1. Start MessageBus
        self.message_bus.start()

        # 2. Start AgentRegistry
        self.registry.start()

        # 3. Initialize tool registry
        self._init_tool_registry()

        # 4. Create and register Agents
        self._create_agents()

        # 5. Start all Agents
        for agent in self._agents.values():
            agent.start()

        self._running = True
        logger.info(f"Agent Network started with {len(self._agents)} agents")

    def stop(self) -> None:
        """Stop network"""
        if not self._running:
            return

        logger.info("Stopping Agent Network...")

        # Stop all Agents
        for agent in self._agents.values():
            agent.stop()

        # Stop Registry
        self.registry.stop()

        # Stop MessageBus
        self.message_bus.stop()

        self._running = False

        elapsed = time.time() - self._start_time if self._start_time else 0
        logger.info(f"Agent Network stopped. Runtime: {elapsed:.2f}s")

    def _init_tool_registry(self) -> None:
        """Initialize tool registry"""
        try:
            from ..tools.adapters import MCPToolRegistry, RizinTools, TaintTools
            from luodllhack.core import RizinCore

            # Create Rizin core
            logger.info(f"Initializing RizinCore for {self.binary_path}")
            rz = RizinCore(str(self.binary_path))
            self._rizin_core = rz

            # Create tool registry
            self._tool_registry = MCPToolRegistry()
            self._tool_registry.register_adapter(RizinTools(rz))
            logger.info("RizinTools registered")

            # Attempt to create taint engine (optional)
            try:
                from luodllhack.analysis.taint import TaintEngine
                taint_engine = TaintEngine(rz)
                self._taint_engine = taint_engine
                self._tool_registry.register_adapter(TaintTools(taint_engine))
                logger.info("TaintTools registered")
            except Exception as te:
                logger.warning(f"TaintEngine not available: {te}")
                self._taint_engine = None

            # Attempt to register verification tools (optional)
            try:
                from ..tools.adapters import VerificationTools
                self._tool_registry.register_adapter(
                    VerificationTools(self.binary_path, self._taint_engine)
                )
                logger.info("VerificationTools registered")
            except Exception as ve:
                logger.warning(f"VerificationTools not available: {ve}")

            tool_count = len(self._tool_registry.list_tools())
            logger.info(f"Tool registry initialized with {tool_count} tools")

        except Exception as e:
            logger.error(f"Failed to initialize tool registry: {e}")
            import traceback
            traceback.print_exc()
            # Create empty tool registry instead of None
            try:
                from ..tools.adapters import MCPToolRegistry
                self._tool_registry = MCPToolRegistry()
                logger.warning("Created empty tool registry as fallback")
            except Exception:
                self._tool_registry = None

    def _create_agents(self) -> None:
        """Create all Agents"""
        from .analyzer_agent import AnalyzerAgent
        from .validation import ValidationAgent
        from .exploiter import ExploiterAgent
        from .critic import CriticAgent

        # Create AnalyzerAgent (Discovery)
        if self.config.enable_analyzer:
            analyzer = AnalyzerAgent(
                agent_id="analyzer-1",
                tool_registry=self._tool_registry,
                message_bus=self.message_bus,
                shared_state=self.shared_state,
                llm_pool=self.llm_pool,
                agent_registry=self.registry,
                max_react_iterations=self.config.max_react_iterations,
            )
            self._agents["analyzer-1"] = analyzer
            self.registry.register(analyzer)

        # Create ValidationAgent (Verification)
        if self.config.enable_validator:
            validator = ValidationAgent(
                agent_id="validator-1",
                tool_registry=self._tool_registry,
                message_bus=self.message_bus,
                shared_state=self.shared_state,
                llm_pool=self.llm_pool,
                agent_registry=self.registry,
            )
            self._agents["validator-1"] = validator
            self.registry.register(validator)

        # Create ExploiterAgent (Exploitation)
        if self.config.enable_exploiter:
            exploiter = ExploiterAgent(
                agent_id="exploiter-1",
                tool_registry=self._tool_registry,
                message_bus=self.message_bus,
                shared_state=self.shared_state,
                llm_pool=self.llm_pool,
                agent_registry=self.registry,
            )
            self._agents["exploiter-1"] = exploiter
            self.registry.register(exploiter)

        # Create CriticAgent (Quality Control)
        if self.config.enable_critic:
            critic = CriticAgent(
                agent_id="critic-1",
                tool_registry=self._tool_registry,
                message_bus=self.message_bus,
                shared_state=self.shared_state,
                llm_pool=self.llm_pool,
                agent_registry=self.registry,
            )
            self._agents["critic-1"] = critic
            self.registry.register(critic)

        logger.info(f"Created {len(self._agents)} agents: {list(self._agents.keys())}")

    # =========================================================================
    # Analysis Entry Point
    # =========================================================================

    def run_analysis(
        self,
        exports: Dict[str, int] = None,
        focus_function: str = None,
    ) -> Dict[str, Any]:
        """
        Run full analysis

        Args:
            exports: Export functions dictionary
            focus_function: Function name to focus analysis on

        Returns:
            Analysis results
        """
        if not self._running:
            self.start()

        logger.info("Starting vulnerability analysis...")

        # Initialize analysis context
        context = AnalysisContext(
            binary_path=str(self.binary_path),
            exports=exports or {},
        )
        self.shared_state.set_context(context)

        # Create initial tasks
        initial_tasks = self._create_initial_tasks(exports, focus_function)

        # Dispatch tasks
        for task in initial_tasks:
            self._dispatch_task(task)

        # Wait for completion
        self._wait_for_completion(timeout=self.config.task_timeout)

        # Collect results
        return self._collect_results()

    def _create_initial_tasks(
        self,
        exports: Dict[str, int] = None,
        focus_function: str = None,
    ) -> List[TaskAssignment]:
        """Create initial tasks"""
        tasks = []

        if focus_function:
            # Focus analysis on a single function
            if exports and focus_function in exports:
                tasks.append(TaskAssignment.create(
                    task_type="initial_taint_scan",
                    parameters={
                        "func_name": focus_function,
                        "func_address": exports[focus_function],
                    },
                    priority=9
                ))
        else:
            # Full analysis
            # 1. Scan dangerous imports
            tasks.append(TaskAssignment.create(
                task_type="scan_dangerous_imports",
                parameters={"max_apis": 20},
                priority=8
            ))

            # 2. Find attack surface
            tasks.append(TaskAssignment.create(
                task_type="find_attack_surface",
                parameters={},
                priority=7
            ))

            # 3. Analyze export functions (if any)
            if exports:
                tasks.append(TaskAssignment.create(
                    task_type="analyze_exports",
                    parameters={"exports": exports},
                    priority=6
                ))

        return tasks

    def _dispatch_task(self, task: TaskAssignment) -> None:
        """Dispatch task to appropriate Agent"""
        # Find Agent capable of handling the task
        best_agent = None
        best_confidence = 0.0

        for agent_id, agent in self._agents.items():
            confidence = agent.can_handle(task)
            if confidence > best_confidence:
                best_confidence = confidence
                best_agent = agent

        if best_agent:
            best_agent.assign_task(task)
            self.registry.increment_load(best_agent.agent_id)
            logger.info(f"Task {task.task_id} dispatched to {best_agent.agent_id}")
        else:
            logger.warning(f"No agent can handle task {task.task_type}")

    def _wait_for_completion(self, timeout: float = 300.0) -> None:
        """
        Wait for all tasks to complete

        Implements task delegation flow:
        1. Wait for Agents to process tasks
        2. Collect Agent results
        3. Extract next_tasks from results
        4. Dispatch next_tasks to other Agents
        5. Repeat until no new tasks
        """
        start = time.time()
        processed_results: set = set()

        while time.time() - start < timeout:
            # Collect completed task results and process next_tasks
            new_tasks_dispatched = self._process_agent_results(processed_results)

            # Check if all Agents are idle
            all_idle = all(
                agent.get_pending_task_count() == 0
                for agent in self._agents.values()
            )

            if all_idle and not new_tasks_dispatched:
                logger.info("All tasks completed")
                break

            time.sleep(0.5)
        else:
            logger.warning(f"Analysis timed out after {timeout}s")

    def _process_agent_results(self, processed_results: set) -> bool:
        """
        Process Agent results, dispatch next_tasks

        Args:
            processed_results: Set of processed result IDs

        Returns:
            Whether new tasks were dispatched
        """
        new_tasks_dispatched = False

        for agent in self._agents.values():
            # Get Agent's results
            results = agent.get_completed_results()

            for result in results:
                result_key = f"{result.agent_id}:{result.task_id}"
                if result_key in processed_results:
                    continue

                processed_results.add(result_key)
                self._results.append(result)

                # Process next_tasks
                if result.next_tasks:
                    for next_task in result.next_tasks:
                        self._dispatch_task(next_task)
                        new_tasks_dispatched = True
                        logger.info(
                            f"Dispatched next_task {next_task.task_type} "
                            f"from {result.agent_id}"
                        )

                # Collect findings
                if result.findings:
                    self._all_findings.extend(result.findings)

        return new_tasks_dispatched

    def _collect_results(self) -> Dict[str, Any]:
        """Collect analysis results"""
        # Use collected findings (from _process_agent_results)
        all_findings = list(self._all_findings)
        all_artifacts = {}

        for agent in self._agents.values():
            # Also collect Agent's current findings (may have unprocessed ones)
            try:
                findings = agent.get_all_findings()
                all_findings.extend(findings)
            except Exception as e:
                logger.warning(f"Failed to get findings from {agent.agent_id}: {e}")

            # Collect statistics
            try:
                stats = agent.get_network_stats()
                all_artifacts[agent.agent_id] = {
                    "role": agent.role,
                    "stats": stats,
                }
            except Exception as e:
                logger.warning(f"Failed to get stats from {agent.agent_id}: {e}")

        # Deduplicate
        unique_findings = self._deduplicate_findings(all_findings)

        # Sort by severity
        unique_findings.sort(
            key=lambda f: {
                "Critical": 0, "High": 1, "Medium": 2, "Low": 3
            }.get(f.get("severity", "Medium"), 2)
        )

        elapsed = time.time() - self._start_time if self._start_time else 0

        return {
            "binary_path": str(self.binary_path),
            "findings": unique_findings,
            "findings_count": len(unique_findings),
            "agents_used": list(self._agents.keys()),
            "agent_stats": all_artifacts,
            "elapsed_time": elapsed,
            "summary": self._generate_summary(unique_findings),
        }

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings"""
        seen = set()
        unique = []

        for finding in findings:
            # Deduplicate based on address and vulnerability type
            key = (
                finding.get("address"),
                finding.get("vuln_type"),
                finding.get("sink_api"),
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _generate_summary(self, findings: List[Dict]) -> Dict[str, Any]:
        """Generate analysis summary"""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        vuln_type_counts = {}

        for finding in findings:
            severity = finding.get("severity", "Medium")
            if severity in severity_counts:
                severity_counts[severity] += 1

            vuln_type = finding.get("vuln_type", "UNKNOWN")
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1

        # Determine overall risk level
        if severity_counts["Critical"] > 0:
            risk_level = "Critical"
        elif severity_counts["High"] > 0:
            risk_level = "High"
        elif severity_counts["Medium"] > 0:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "risk_level": risk_level,
            "by_severity": severity_counts,
            "by_vuln_type": vuln_type_counts,
            "total_findings": len(findings),
        }



# =============================================================================
# Factory Functions
# =============================================================================

def create_network_runner(
    binary_path: Path,
    config: "LuoDllHackConfig" = None,
    api_key: str = None,
) -> NetworkRunner:
    """
    Create network runner

    Args:
        binary_path: Target binary file
        config: LuoDllHack Configuration
        api_key: LLM API Key

    Returns:
        NetworkRunner instance
    """
    # Create network configuration
    if config:
        network_config = NetworkConfig.from_luodllhack_config(config)
    else:
        network_config = NetworkConfig()

    if api_key:
        network_config.llm_api_key = api_key

    # Create LLM pool
    llm_pool = None
    if network_config.llm_api_key:
        try:
            from .llm_pool import create_pool_from_config
            llm_pool = create_pool_from_config(config)
        except Exception as e:
            logger.warning(f"Failed to create LLM pool: {e}")

    return NetworkRunner(binary_path, network_config, llm_pool)
