# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/shared_state.py
Shared State Management - Thread-safe multi-agent state coordination

Features:
    - Finding de-duplication and merging
    - Atomic task preemption
    - Progress tracking
    - State snapshot (for LLM context use)

Phase 3 optimization:
    - Read-write lock separation (allows multiple reads, single write)
    - Versioned snapshot (optimistic locking support)
    - apply_if_unchanged optimistic update
"""

import threading
import copy
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
from contextlib import contextmanager
import time
import json
import hashlib
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Read-Write Lock Implementation
# =============================================================================

class ReadWriteLock:
    """
    Read-Write Lock - Allows multiple reads, single write

    Features:
    - Multiple read operations can be concurrent
    - Write operations require exclusivity
    - Write operations have higher priority than read operations (prevents write starvation)
    """

    def __init__(self):
        self._read_ready = threading.Condition(threading.Lock())
        self._readers = 0
        self._writers_waiting = 0
        self._writer_active = False

    @contextmanager
    def read_lock(self):
        """Acquire read lock (allows concurrent reads)"""
        with self._read_ready:
            # If there is a writer waiting or active, then wait
            while self._writers_waiting > 0 or self._writer_active:
                self._read_ready.wait()
            self._readers += 1

        try:
            yield
        finally:
            with self._read_ready:
                self._readers -= 1
                if self._readers == 0:
                    self._read_ready.notify_all()

    @contextmanager
    def write_lock(self):
        """Acquire write lock (exclusive)"""
        with self._read_ready:
            self._writers_waiting += 1
            # Wait for all readers to complete
            while self._readers > 0 or self._writer_active:
                self._read_ready.wait()
            self._writers_waiting -= 1
            self._writer_active = True

        try:
            yield
        finally:
            with self._read_ready:
                self._writer_active = False
                self._read_ready.notify_all()


# =============================================================================
# Versioned Snapshot
# =============================================================================

@dataclass
class StateSnapshot:
    """
    State snapshot with version number

    Used for optimistic lock updates: checking if version number has changed
    """
    version: int
    timestamp: float
    findings: Dict[str, Any]
    context: Optional[Dict[str, Any]]
    step: int
    max_steps: int
    tasks: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "findings": self.findings,
            "context": self.context,
            "step": self.step,
            "max_steps": self.max_steps,
            "tasks": self.tasks,
        }


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class Finding:
    """
    Vulnerability Findings

    Represents potential vulnerabilities discovered by Agents.
    """
    finding_id: str
    pattern_offset: Optional[int] = None      # Exact offset controlled by EIP
    bad_chars_detected: Optional[List[int]] = field(default_factory=list)  # Detected bad characters
    safe_chars_count: Optional[int] = None    # Number of safe characters
    crash_info: Optional[Dict[str, Any]] = field(default_factory=dict)  # Crash information

    def get_dedup_key(self) -> str:
        """Generate de-duplication key"""
        key_parts = [
            str(self.vuln_type) if self.vuln_type else "",
            str(self.address) if self.address else "",
            str(self.function) if self.function else "",
            str(self.sink_api) if self.sink_api else ""
        ]
        key_str = ":".join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()[:16]

    def merge_from(self, other: "Finding") -> None:
        """Merge information from another finding"""
        # Keep higher confidence
        if other.confidence > self.confidence:
            self.confidence = other.confidence

        # Merge evidence
        for e in other.evidence:
            if e not in self.evidence:
                self.evidence.append(e)

        # Add validators
        if other.discovered_by and other.discovered_by not in self.verified_by:
            self.verified_by.append(other.discovered_by)

        # Merge new fields
        if other.pattern_offset is not None:
            self.pattern_offset = other.pattern_offset
        if other.bad_chars_detected:
            self.bad_chars_detected = other.bad_chars_detected
        if other.safe_chars_count is not None:
            self.safe_chars_count = other.safe_chars_count
        if other.crash_info:
            self.crash_info.update(other.crash_info)

        if other.poc_path:
            self.poc_path = other.poc_path
        if other.harness_path:
            self.harness_path = other.harness_path

        if other.is_false_positive:
            self.is_false_positive = True
            if other.false_positive_reason:
                self.false_positive_reason = other.false_positive_reason

        # Update time
        self.updated_at = time.time()

        # Merge metadata
        self.metadata.update(other.metadata)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create from dictionary"""
        return cls(**data)


@dataclass
class AnalysisContext:
    """
    Analysis Context

    Stores basic information of the target binary.
    """
    binary_path: str
    binary_name: str = ""
    image_base: int = 0
    arch: str = "x64"                 # x64, x86
    exports: Dict[str, int] = field(default_factory=dict)
    imports: Dict[int, str] = field(default_factory=dict)
    dangerous_apis: List[Dict] = field(default_factory=list)
    analyzed_functions: Set[int] = field(default_factory=set)
    taint_paths: List[Dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.binary_name and self.binary_path:
            import os
            self.binary_name = os.path.basename(self.binary_path)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (serializable)"""
        return {
            "binary_path": self.binary_path,
            "binary_name": self.binary_name,
            "image_base": self.image_base,
            "arch": self.arch,
            "exports": self.exports,
            "imports": {str(k): v for k, v in self.imports.items()},
            "dangerous_apis": self.dangerous_apis,
            "analyzed_functions": list(self.analyzed_functions),
            "taint_paths": self.taint_paths,
            "metadata": self.metadata,
        }


# =============================================================================
# Shared State Manager
# =============================================================================

class SharedState:
    """
    Thread-safe shared state manager

    Used for state coordination among multiple Agents:
    - Finding storage and de-duplication
    - Task tracking
    - Progress management
    - Agent status monitoring
    """

    def __init__(self, max_steps: int = 50):
        """
        Initialize shared state

        Args:
            max_steps: Maximum analysis steps
        """
        # Phase 3: Read-write lock separation
        self._rwlock = ReadWriteLock()
        self._version: int = 0  # Version number for optimistic locking

        # Core state
        self._findings: Dict[str, Finding] = {}         # finding_id -> Finding
        self._dedup_index: Dict[str, str] = {}          # dedup_key -> finding_id
        self._context: Optional[AnalysisContext] = None

        # Progress tracking
        self._current_step: int = 0
        self._max_steps: int = max_steps
        self._should_stop: bool = False

        # Task tracking
        self._completed_tasks: Set[str] = set()
        self._in_progress_tasks: Dict[str, str] = {}    # task_id -> agent_id
        self._failed_tasks: Dict[str, str] = {}         # task_id -> error

        # Agent status
        self._agent_status: Dict[str, Dict] = {}

        # Statistics
        self._metrics: Dict[str, int] = defaultdict(int)
        self._start_time: float = time.time()

        logger.info(f"SharedState initialized with max_steps={max_steps}")

    # =========================================================================
    # Context Management
    # =========================================================================

    def initialize_context(self, context: AnalysisContext) -> None:
        """
        Initialize analysis context

        Args:
            context: Analysis context
        """
        with self._rwlock.write_lock():
            self._context = context
            self._start_time = time.time()
            self._version += 1
            logger.info(f"Context initialized for {context.binary_name}")

    def set_context(self, context: AnalysisContext) -> None:
        """Alias for initialize_context, for compatibility"""
        self.initialize_context(context)

    def get_context(self) -> Optional[AnalysisContext]:
        """Get analysis context"""
        with self._rwlock.read_lock():
            return self._context

    def update_context(self, **kwargs) -> None:
        """
        Update context fields

        Args:
            **kwargs: Fields to update
        """
        with self._rwlock.write_lock():
            if self._context:
                for key, value in kwargs.items():
                    if hasattr(self._context, key):
                        setattr(self._context, key, value)
                self._version += 1

    # =========================================================================
    # Finding Management
    # =========================================================================

    def add_finding(self, finding: Finding) -> bool:
        """
        Add finding (with de-duplication)

        Args:
            finding: Finding

        Returns:
            True=newly added, False=merged into existing
        """
        with self._rwlock.write_lock():
            dedup_key = finding.get_dedup_key()

            # Check if already exists
            if dedup_key in self._dedup_index:
                existing_id = self._dedup_index[dedup_key]
                existing = self._findings[existing_id]
                existing.merge_from(finding)
                self._metrics["findings_merged"] += 1
                self._version += 1
                logger.debug(f"Finding merged: {existing_id}")
                return False

            # Newly added
            self._findings[finding.finding_id] = finding
            self._dedup_index[dedup_key] = finding.finding_id
            self._metrics["findings_added"] += 1
            self._version += 1
            logger.info(f"Finding added: {finding.finding_id} ({finding.vuln_type})")
            return True

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get a single finding"""
        with self._rwlock.read_lock():
            return self._findings.get(finding_id)

    def get_findings(
        self,
        status: Optional[str] = None,
        min_confidence: float = 0.0,
        vuln_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Finding]:
        """
        Get finding list

        Args:
            status: Filter status
            min_confidence: Minimum confidence
            vuln_type: Filter vulnerability type
            severity: Filter severity
            limit: Maximum quantity

        Returns:
            Finding list (descending order by confidence)
        """
        with self._rwlock.read_lock():
            findings = list(self._findings.values())

        # Filter
        if status:
            findings = [f for f in findings if f.status == status]
        if min_confidence > 0:
            findings = [f for f in findings if f.confidence >= min_confidence]
        if vuln_type:
            findings = [f for f in findings if f.vuln_type == vuln_type]
        if severity:
            findings = [f for f in findings if f.severity == severity]

        # Sort (descending confidence)
        findings.sort(key=lambda f: -f.confidence)

        return findings[:limit]

    def get_all_findings(self) -> List[Finding]:
        """Get all findings (no filtering, no limits)"""
        with self._rwlock.read_lock():
            findings = list(self._findings.values())
        findings.sort(key=lambda f: -f.confidence)
        return findings

    def update_finding(
        self,
        finding_id: str,
        status: Optional[str] = None,
        verified_by: Optional[str] = None,
        poc_code: Optional[str] = None,
        confidence: Optional[float] = None,
        **kwargs
    ) -> bool:
        """
        Update finding

        Args:
            finding_id: Finding ID
            status: New status
            verified_by: Verifier
            poc_code: PoC code
            confidence: New confidence
            **kwargs: Other fields

        Returns:
            Whether successful
        """
        with self._rwlock.write_lock():
            if finding_id not in self._findings:
                return False

            finding = self._findings[finding_id]

            if status:
                finding.status = status
            if verified_by and verified_by not in finding.verified_by:
                finding.verified_by.append(verified_by)
            if poc_code:
                finding.poc_code = poc_code
            if confidence is not None:
                finding.confidence = confidence

            for key, value in kwargs.items():
                if hasattr(finding, key):
                    setattr(finding, key, value)

            finding.updated_at = time.time()
            self._version += 1
            return True

    def get_findings_count(self) -> Dict[str, int]:
        """Get finding statistics"""
        with self._rwlock.read_lock():
            counts = {
                "total": len(self._findings),
                "pending": 0,
                "verified": 0,
                "rejected": 0,
                "exploited": 0,
                "false_positive": 0,
                "high_confidence": 0,
            }
            for f in self._findings.values():
                if f.status in counts:
                    counts[f.status] += 1
                if f.confidence >= 0.7:
                    counts["high_confidence"] += 1
            return counts

    def update_finding_review_status(
        self,
        finding_id: str,
        is_false_positive: bool,
        review_reasons: Optional[List[str]] = None,
        final_confidence: Optional[float] = None
    ) -> bool:
        """
        Update AI review status of a finding

        Args:
            finding_id: Finding ID
            is_false_positive: Whether it is a false positive
            review_reasons: Reasons for false positive
            final_confidence: Final confidence

        Returns:
            Whether successfully updated
        """
        with self._rwlock.write_lock():
            if finding_id not in self._findings:
                return False

            finding = self._findings[finding_id]

            # Update confidence (reduce confidence if it is a false positive)
            if final_confidence is not None:
                finding.confidence = final_confidence
            elif is_false_positive and finding.confidence > 0.1:
                # If it is a false positive and confidence is high, reduce it to a lower value
                finding.confidence = 0.1

            # Add review-related metadata
            finding.is_false_positive = is_false_positive
            if review_reasons:
                finding.false_positive_reason = "; ".join(review_reasons) if isinstance(review_reasons, list) else str(review_reasons)
            
            # Also keep metadata for reference by old code
            finding.metadata['is_false_positive'] = is_false_positive
            if review_reasons:
                finding.metadata['review_reasons'] = review_reasons

            finding.updated_at = time.time()
            self._version += 1

            logger.info(f"Finding {finding_id} review status updated: "
                       f"is_false_positive={is_false_positive}, "
                       f"confidence={finding.confidence}")
            return True

    # =========================================================================
    # Task Tracking
    # =========================================================================

    def claim_task(self, task_id: str, agent_id: str) -> bool:
        """
        Atomic task preemption

        Args:
            task_id: Task ID
            agent_id: Agent ID

        Returns:
            Whether preemption was successful
        """
        with self._rwlock.write_lock():
            if task_id in self._completed_tasks:
                logger.debug(f"Task {task_id} already completed")
                return False
            if task_id in self._in_progress_tasks:
                logger.debug(f"Task {task_id} already in progress by {self._in_progress_tasks[task_id]}")
                return False

            self._in_progress_tasks[task_id] = agent_id
            self._metrics["tasks_claimed"] += 1
            self._version += 1
            logger.debug(f"Task {task_id} claimed by {agent_id}")
            return True

    def complete_task(self, task_id: str, success: bool = True, error: str = None) -> None:
        """
        Mark task as completed

        Args:
            task_id: Task ID
            success: Whether successful
            error: Error message
        """
        with self._rwlock.write_lock():
            if task_id in self._in_progress_tasks:
                del self._in_progress_tasks[task_id]

            if success:
                self._completed_tasks.add(task_id)
                self._metrics["tasks_completed"] += 1
            else:
                self._failed_tasks[task_id] = error or "Unknown error"
                self._metrics["tasks_failed"] += 1

            self._version += 1
            logger.debug(f"Task {task_id} {'completed' if success else 'failed'}")

    def release_task(self, task_id: str) -> None:
        """
        Release task (for timeout or cancellation)

        Args:
            task_id: Task ID
        """
        with self._rwlock.write_lock():
            if task_id in self._in_progress_tasks:
                del self._in_progress_tasks[task_id]
                self._metrics["tasks_released"] += 1
                self._version += 1

    def is_task_done(self, task_id: str) -> bool:
        """Check if task is completed"""
        with self._rwlock.read_lock():
            return task_id in self._completed_tasks

    def get_task_status(self, task_id: str) -> str:
        """Get task status"""
        with self._rwlock.read_lock():
            if task_id in self._completed_tasks:
                return "completed"
            if task_id in self._in_progress_tasks:
                return f"in_progress:{self._in_progress_tasks[task_id]}"
            if task_id in self._failed_tasks:
                return f"failed:{self._failed_tasks[task_id]}"
            return "pending"

    # =========================================================================
    # Progress Control
    # =========================================================================

    def increment_step(self) -> int:
        """Increment and return the current step"""
        with self._rwlock.write_lock():
            self._current_step += 1
            self._version += 1
            return self._current_step

    def get_step(self) -> int:
        """Get current step"""
        with self._rwlock.read_lock():
            return self._current_step

    def set_max_steps(self, max_steps: int) -> None:
        """Set maximum steps"""
        with self._rwlock.write_lock():
            self._max_steps = max_steps
            self._version += 1

    def extend_steps(self, additional: int) -> int:
        """
        Extend steps

        Args:
            additional: Additional steps

        Returns:
            New maximum steps
        """
        with self._rwlock.write_lock():
            self._max_steps += additional
            self._version += 1
            logger.info(f"Steps extended by {additional}, new max: {self._max_steps}")
            return self._max_steps

    def should_stop(self) -> bool:
        """Check if analysis should stop"""
        with self._rwlock.read_lock():
            return self._should_stop or self._current_step >= self._max_steps

    def request_stop(self, reason: str = "manual") -> None:
        """Request to stop analysis"""
        with self._rwlock.write_lock():
            self._should_stop = True
            self._version += 1
            logger.info(f"Stop requested: {reason}")

    def reset_stop(self) -> None:
        """Reset stop flag"""
        with self._rwlock.write_lock():
            self._should_stop = False
            self._version += 1

    # =========================================================================
    # Agent Status
    # =========================================================================

    def update_agent_status(self, agent_id: str, status: Dict) -> None:
        """Update Agent status"""
        with self._rwlock.write_lock():
            self._agent_status[agent_id] = {
                **status,
                "updated_at": time.time()
            }
            self._version += 1

    def get_agent_status(self, agent_id: str) -> Optional[Dict]:
        """Get Agent status"""
        with self._rwlock.read_lock():
            return self._agent_status.get(agent_id)

    def get_all_agent_status(self) -> Dict[str, Dict]:
        """Get all Agent status"""
        with self._rwlock.read_lock():
            return self._agent_status.copy()

    # =========================================================================
    # State Snapshot (for LLM context use)
    # =========================================================================

    def get_snapshot(self, compact: bool = True) -> Dict[str, Any]:
        """
        Get state snapshot

        Args:
            compact: Whether to compress (reduce tokens)

        Returns:
            State snapshot dictionary
        """
        with self._rwlock.read_lock():
            findings = list(self._findings.values())

            # Statistics
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            type_counts: Dict[str, int] = defaultdict(int)
            high_conf_count = 0

            for f in findings:
                if f.severity in severity_counts:
                    severity_counts[f.severity] += 1
                type_counts[f.vuln_type] += 1
                if f.confidence >= 0.7:
                    high_conf_count += 1

            # Recent discoveries (compressed format)
            recent = sorted(findings, key=lambda x: -x.created_at)[:5]
            if compact:
                recent_data = [
                    {
                        "t": f.vuln_type,
                        "c": round(f.confidence, 2),
                        "s": f.status,
                        "a": f.address
                    }
                    for f in recent
                ]
            else:
                recent_data = [f.to_dict() for f in recent]

            snapshot = {
                "step": self._current_step,
                "max_steps": self._max_steps,
                "findings": {
                    "total": len(findings),
                    "high_confidence": high_conf_count,
                    "verified": sum(1 for f in findings if f.status == "verified"),
                    "with_poc": sum(1 for f in findings if f.poc_code),
                },
                "severity": severity_counts,
                "types": dict(sorted(type_counts.items(), key=lambda x: -x[1])[:8]),
                "recent": recent_data,
                "tasks": {
                    "completed": len(self._completed_tasks),
                    "in_progress": len(self._in_progress_tasks),
                    "failed": len(self._failed_tasks),
                },
                "elapsed": round(time.time() - self._start_time, 1),
            }

            return snapshot

    def get_summary(self) -> str:
        """Get text summary"""
        snapshot = self.get_snapshot()
        lines = [
            f"Step {snapshot['step']}/{snapshot['max_steps']}",
            f"Findings: {snapshot['findings']['total']} (verified: {snapshot['findings']['verified']}, high-conf: {snapshot['findings']['high_confidence']})",
            f"Severity: {snapshot['severity']}",
            f"Tasks: completed={snapshot['tasks']['completed']}, in_progress={snapshot['tasks']['in_progress']}",
        ]
        return "\n".join(lines)

    def get_versioned_snapshot(self) -> StateSnapshot:
        """
        Get versioned state snapshot

        Used for optimistic locking: check if version has changed in apply_if_unchanged

        Returns:
            StateSnapshot: Complete state snapshot containing version number
        """
        with self._rwlock.read_lock():
            # Deep copy finding data
            findings_copy = {
                fid: {
                    "id": f.finding_id,
                    "type": f.vuln_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "status": f.status,
                    "address": f.address,
                    "function": f.function,
                }
                for fid, f in self._findings.items()
            }

            # Deep copy context
            context_copy = None
            if self._context:
                context_copy = self._context.to_dict()

            # Task state
            tasks_copy = {
                "completed": list(self._completed_tasks),
                "in_progress": dict(self._in_progress_tasks),
                "failed": dict(self._failed_tasks),
            }

            return StateSnapshot(
                version=self._version,
                timestamp=time.time(),
                findings=findings_copy,
                context=context_copy,
                step=self._current_step,
                max_steps=self._max_steps,
                tasks=tasks_copy,
            )

    def get_version(self) -> int:
        """Get current state version number"""
        with self._rwlock.read_lock():
            return self._version

    # =========================================================================
    # Statistics and Monitoring
    # =========================================================================

    def get_metrics(self) -> Dict[str, Any]:
        """Get all statistical metrics"""
        with self._rwlock.read_lock():
            return {
                **dict(self._metrics),
                "findings_total": len(self._findings),
                "tasks_completed": len(self._completed_tasks),
                "tasks_in_progress": len(self._in_progress_tasks),
                "elapsed_time": time.time() - self._start_time,
                "state_version": self._version,
            }

    def reset(self) -> None:
        """Reset all state"""
        with self._rwlock.write_lock():
            self._findings.clear()
            self._dedup_index.clear()
            self._completed_tasks.clear()
            self._in_progress_tasks.clear()
            self._failed_tasks.clear()
            self._agent_status.clear()
            self._current_step = 0
            self._should_stop = False
            self._metrics.clear()
            self._start_time = time.time()
            self._version = 0
            logger.info("SharedState reset")

    # =========================================================================
    # Optimistic Lock Updates
    # =========================================================================

    def apply_if_unchanged(
        self,
        expected_version: int,
        update_func: callable,
        *args,
        **kwargs
    ) -> Tuple[bool, Any]:
        """
        Optimistic lock update: Apply update only when the version has not changed.

        Use case:
        1. Agent gets a snapshot for analysis.
        2. Analysis is complete, check if the state was modified by other agents.
        3. If not modified, atomically apply the update.

        Args:
            expected_version: Expected version number (from previous snapshot)
            update_func: Update function, receives self as first argument
            *args, **kwargs: Arguments passed to update_func

        Returns:
            Tuple[bool, Any]:
                - bool: Whether the update was successfully applied
                - Any: Return value of update_func (on success) or None (on failure)

        Example:
            # Get snapshot
            snapshot = state.get_versioned_snapshot()
            version = snapshot.version

            # Analyze...
            result = analyze(snapshot)

            # Try to apply update
            def do_update(state, finding):
                state.add_finding(finding)
                return True

            success, result = state.apply_if_unchanged(version, do_update, new_finding)
            if not success:
                # Version changed, need to fetch new snapshot and retry
                pass
        """
        with self._rwlock.write_lock():
            if self._version != expected_version:
                logger.debug(
                    f"Optimistic lock failed: expected v{expected_version}, "
                    f"current v{self._version}"
                )
                return False, None

            try:
                # Execute update function
                result = update_func(self, *args, **kwargs)
                # Version number is automatically incremented in write methods
                return True, result
            except Exception as e:
                logger.error(f"Update function failed: {e}")
                return False, None

    def compare_and_update_finding(
        self,
        expected_version: int,
        finding_id: str,
        updates: Dict[str, Any]
    ) -> Tuple[bool, Optional[Finding]]:
        """
        Optimistic lock update for a single finding.

        Simplified apply_if_unchanged for common single finding update scenarios.

        Args:
            expected_version: Expected version number
            finding_id: Finding ID
            updates: Fields to update

        Returns:
            Tuple[bool, Optional[Finding]]:
                - bool: Whether successful
                - Finding: Updated finding (on success) or None
        """
        with self._rwlock.write_lock():
            if self._version != expected_version:
                return False, None

            if finding_id not in self._findings:
                return False, None

            finding = self._findings[finding_id]

            for key, value in updates.items():
                if hasattr(finding, key):
                    setattr(finding, key, value)

            finding.updated_at = time.time()
            self._version += 1

            return True, finding
