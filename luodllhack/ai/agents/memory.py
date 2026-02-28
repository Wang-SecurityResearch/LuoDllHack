# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/memory.py
Agent Memory System - Long-term memory and learning mechanism

Provides the Agent with the ability to learn from historical experience
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import json
import time
from pathlib import Path
import logging

if __name__ != "__main__":
    from .base import TaskAssignment, AgentResult

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    """Single memory entry"""
    timestamp: float
    task_type: str
    parameters: Dict[str, Any]
    result_summary: Dict[str, Any]
    success: bool
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentMemory:
    """
    Agent long-term memory system
    
    Features:
        - Record successful and failed task patterns
        - Identify false positive patterns
        - Tool usage statistics
        - Learn heuristic rules
    """
    
    # Successful patterns
    successful_patterns: List[MemoryEntry] = field(default_factory=list)
    
    # Failure patterns (including false positives)
    failure_patterns: List[MemoryEntry] = field(default_factory=list)
    
    # Tool usage statistics
    tool_usage_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Learned heuristic rules
    learned_heuristics: List[str] = field(default_factory=list)
    
    # False positive features repository
    false_positive_features: List[Dict[str, Any]] = field(default_factory=list)
    
    # True positive features repository
    true_positive_features: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_experience(self, task: "TaskAssignment", result: "AgentResult") -> None:
        """
        Learn from task results
        
        Args:
            task: Task assignment
            result: Execution result
        """
        entry = MemoryEntry(
            timestamp=time.time(),
            task_type=task.task_type,
            parameters=task.parameters.copy(),
            result_summary={
                "success": result.success,
                "findings_count": len(result.findings),
                "execution_time": result.execution_time,
                "error": result.error
            },
            success=result.success,
            tags=self._extract_tags(task, result),
            metadata=result.metadata.copy() if result.metadata else {}
        )
        
        if result.success:
            self.successful_patterns.append(entry)
            logger.debug(f"Added successful pattern: {task.task_type}")
            
            # Extract true positive features
            if result.findings:
                self._extract_tp_features(task, result)
        else:
            self.failure_patterns.append(entry)
            logger.debug(f"Added failure pattern: {task.task_type}")
            
            # Extract false positive features
            if "false_positive" in str(result.error).lower():
                self._extract_fp_features(task, result)
        
        # Update tool usage statistics
        self._update_tool_stats(task, result)
    
    def find_similar_cases(
        self,
        task: "TaskAssignment",
        limit: int = 5,
        success_only: bool = True
    ) -> List[MemoryEntry]:
        """
        Find similar cases
        
        Args:
            task: Current task
            limit: Return quantity limit
            success_only: Only return successful cases
            
        Returns:
            Similar cases list
        """
        pool = self.successful_patterns if success_only else (
            self.successful_patterns + self.failure_patterns
        )
        
        # Simple implementation: match based on task type
        similar = [e for e in pool if e.task_type == task.task_type]
        
        # Sort by timestamp, return the most recent
        similar.sort(key=lambda x: x.timestamp, reverse=True)
        return similar[:limit]
    
    def is_likely_false_positive(self, finding: Dict[str, Any]) -> tuple[bool, float, List[str]]:
        """
        Determine if the finding is likely a false positive
        
        Args:
            finding: Vulnerability finding
            
        Returns:
            (Is likely false positive, confidence, reason list)
        """
        reasons = []
        fp_score = 0.0
        
        # Check if it matches known false positive features
        for fp_feature in self.false_positive_features:
            match_score = self._match_feature(finding, fp_feature)
            if match_score > 0.7:
                fp_score = max(fp_score, match_score)
                reasons.append(f"Matches known FP pattern: {fp_feature.get('description', 'unknown')}")
        
        # Check function name patterns
        function_name = finding.get("function", "")
        if function_name:
            fp_functions = ["DllMain", "DllEntryPoint", "_DllMainCRTStartup"]
            if any(fp_func in function_name for fp_func in fp_functions):
                fp_score = max(fp_score, 0.6)
                reasons.append(f"Entry point function: {function_name}")
        
        # Check confidence
        confidence = finding.get("confidence", 1.0)
        if confidence < 0.3:
            fp_score = max(fp_score, 0.5)
            reasons.append(f"Low confidence: {confidence}")
        
        is_fp = fp_score > 0.5
        return is_fp, fp_score, reasons
    
    def get_tool_recommendations(self, task_type: str) -> List[str]:
        """
        Recommend tools based on historical experience
        
        Args:
            task_type: Task type
            
        Returns:
            Recommended tools list
        """
        # Find successful cases for this task type
        similar = [e for e in self.successful_patterns if e.task_type == task_type]
        
        if not similar:
            return []
        
        # Count tool usage frequency
        tool_counts = {}
        for entry in similar:
            tools_used = entry.metadata.get("tools_used", [])
            for tool in tools_used:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        # Sort by frequency
        sorted_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)
        return [tool for tool, count in sorted_tools[:5]]
    
    def learn_heuristic(self, rule: str) -> None:
        """
        Learn new heuristic rules
        
        Args:
            rule: Rule description
        """
        if rule not in self.learned_heuristics:
            self.learned_heuristics.append(rule)
            logger.info(f"Learned new heuristic: {rule}")
    
    def save(self, filepath: Path) -> None:
        """
        Save memory to file
        
        Args:
            filepath: Save path
        """
        data = {
            "successful_patterns": [self._entry_to_dict(e) for e in self.successful_patterns],
            "failure_patterns": [self._entry_to_dict(e) for e in self.failure_patterns],
            "tool_usage_stats": self.tool_usage_stats,
            "learned_heuristics": self.learned_heuristics,
            "false_positive_features": self.false_positive_features,
            "true_positive_features": self.true_positive_features
        }
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Memory saved to {filepath}")
    
    @classmethod
    def load(cls, filepath: Path) -> "AgentMemory":
        """
        Load memory from file
        
        Args:
            filepath: File path
            
        Returns:
            AgentMemory instance
        """
        if not filepath.exists():
            logger.warning(f"Memory file not found: {filepath}")
            return cls()
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        memory = cls()
        memory.successful_patterns = [cls._dict_to_entry(d) for d in data.get("successful_patterns", [])]
        memory.failure_patterns = [cls._dict_to_entry(d) for d in data.get("failure_patterns", [])]
        memory.tool_usage_stats = data.get("tool_usage_stats", {})
        memory.learned_heuristics = data.get("learned_heuristics", [])
        memory.false_positive_features = data.get("false_positive_features", [])
        memory.true_positive_features = data.get("true_positive_features", [])
        
        logger.info(f"Memory loaded from {filepath}")
        return memory
    
    # =========================================================================
    # Internal helper methods
    # =========================================================================
    
    def _extract_tags(self, task: "TaskAssignment", result: "AgentResult") -> List[str]:
        """Extract tags"""
        tags = [task.task_type]
        
        if result.success:
            tags.append("success")
        else:
            tags.append("failure")
        
        # Extract from metadata
        if result.metadata:
            if result.metadata.get("llm_analyzed"):
                tags.append("llm_analyzed")
            if result.metadata.get("timeout"):
                tags.append("timeout")
        
        return tags
    
    def _update_tool_stats(self, task: "TaskAssignment", result: "AgentResult") -> None:
        """Update tool usage statistics"""
        tools_used = result.metadata.get("tools_used", []) if result.metadata else []
        
        for tool in tools_used:
            if tool not in self.tool_usage_stats:
                self.tool_usage_stats[tool] = {
                    "total_calls": 0,
                    "successful_calls": 0,
                    "failed_calls": 0,
                    "avg_execution_time": 0.0
                }
            
            stats = self.tool_usage_stats[tool]
            stats["total_calls"] += 1
            
            if result.success:
                stats["successful_calls"] += 1
            else:
                stats["failed_calls"] += 1
    
    def _extract_fp_features(self, task: "TaskAssignment", result: "AgentResult") -> None:
        """Extract false positive features"""
        feature = {
            "task_type": task.task_type,
            "parameters": task.parameters.copy(),
            "description": f"FP pattern from {task.task_type}",
            "timestamp": time.time()
        }
        self.false_positive_features.append(feature)
    
    def _extract_tp_features(self, task: "TaskAssignment", result: "AgentResult") -> None:
        """Extract true positive features"""
        for finding in result.findings:
            feature = {
                "vuln_type": finding.get("vuln_type"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "description": f"TP pattern: {finding.get('vuln_type')}",
                "timestamp": time.time()
            }
            self.true_positive_features.append(feature)
    
    def _match_feature(self, finding: Dict[str, Any], feature: Dict[str, Any]) -> float:
        """Calculate match score between finding and feature"""
        score = 0.0
        
        # Simple implementation: check vulnerability type match
        if finding.get("vuln_type") == feature.get("vuln_type"):
            score += 0.5
        
        # Check function name match
        if finding.get("function") == feature.get("parameters", {}).get("func_name"):
            score += 0.3
        
        return min(score, 1.0)
    
    @staticmethod
    def _entry_to_dict(entry: MemoryEntry) -> Dict[str, Any]:
        """Convert MemoryEntry to dictionary"""
        return {
            "timestamp": entry.timestamp,
            "task_type": entry.task_type,
            "parameters": entry.parameters,
            "result_summary": entry.result_summary,
            "success": entry.success,
            "tags": entry.tags,
            "metadata": entry.metadata
        }
    
    @staticmethod
    def _dict_to_entry(data: Dict[str, Any]) -> MemoryEntry:
        """Create MemoryEntry from dictionary"""
        return MemoryEntry(
            timestamp=data["timestamp"],
            task_type=data["task_type"],
            parameters=data["parameters"],
            result_summary=data["result_summary"],
            success=data["success"],
            tags=data.get("tags", []),
            metadata=data.get("metadata", {})
        )
