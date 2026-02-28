# -*- coding: utf-8 -*-
"""
luodllhack/ai/react/token_manager.py
Token Manager - Prevents context overflow

Extracted from agent.py, provides:
- Token estimation
- Text truncation
- Observation history management
- Intelligent tool result summarization
"""

import json
from typing import Any, List, Optional


class TokenManager:
    """
    Token Manager - Prevents context overflow

    Functions:
        1. Estimate text token count
        2. Truncate overly long tool results
        3. Manage observation history within token budget
    """

    # Token limit configuration
    MAX_CONTEXT_TOKENS = 100000      # Max context tokens
    SAFETY_MARGIN = 10000            # Safety margin
    MAX_OBSERVATION_TOKENS = 80000   # Max observation history tokens
    MAX_SINGLE_RESULT_TOKENS = 8000  # Max single tool result tokens

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """
        Estimate text token count

        Uses simplified estimation: ~4 chars/token (for mixed EN/CN)
        Actual token count may vary slightly; this is a conservative estimate.
        """
        if not text:
            return 0
        # Estimate using UTF-8 encoded byte count / 4
        return len(text.encode('utf-8', errors='ignore')) // 4

    @classmethod
    def truncate_text(cls, text: str, max_tokens: int = None) -> str:
        """
        Truncate text to specified token count

        Args:
            text: Original text
            max_tokens: Max tokens (defaults to MAX_SINGLE_RESULT_TOKENS)

        Returns:
            Truncated text
        """
        if max_tokens is None:
            max_tokens = cls.MAX_SINGLE_RESULT_TOKENS

        current_tokens = cls.estimate_tokens(text)
        if current_tokens <= max_tokens:
            return text

        # Calculate characters to keep (estimated)
        ratio = max_tokens / current_tokens
        max_chars = int(len(text) * ratio * 0.9)  # 10% safety margin

        # Truncate and add note
        truncated = text[:max_chars]
        return f"{truncated}\n\n[... content truncated, original length: {len(text)} chars, ~{current_tokens} tokens ...]"

    @classmethod
    def truncate_observations(cls, observations: List[str],
                              max_tokens: int = None) -> List[str]:
        """
        Truncate observation history, keeping recent observations

        Strategy:
            1. Keep recent observations (more relevant)
            2. Remove oldest observations
            3. Ensure total token count is within budget

        Args:
            observations: List of observations
            max_tokens: Maximum token count

        Returns:
            Truncated list of observations
        """
        if max_tokens is None:
            max_tokens = cls.MAX_OBSERVATION_TOKENS

        if not observations:
            return observations

        # Calculate tokens from newest to oldest
        total_tokens = 0
        keep_from_index = 0

        for i in range(len(observations) - 1, -1, -1):
            obs_tokens = cls.estimate_tokens(observations[i])
            if total_tokens + obs_tokens > max_tokens:
                keep_from_index = i + 1
                break
            total_tokens += obs_tokens

        if keep_from_index > 0:
            # Add truncation note
            truncated = observations[keep_from_index:]
            dropped_count = keep_from_index
            return [f"[Dropped {dropped_count} early observations to save context space]"] + truncated

        return observations

    @classmethod
    def summarize_result(cls, result: Any, max_chars: int = 3000) -> str:
        """
        Intelligently summarize tool results

        For large results:
            1. Keep key info (vulnerability findings, errors, etc.)
            2. Truncate detailed data
            3. Retain structured summary

        Args:
            result: Tool return result
            max_chars: Max characters limit

        Returns:
            Summary string
        """
        if result is None:
            return "No result"

        # Convert to string
        if isinstance(result, dict):
            result_str = json.dumps(result, indent=2, ensure_ascii=False)
        elif isinstance(result, (list, tuple)):
            result_str = json.dumps(result, indent=2, ensure_ascii=False)
        else:
            result_str = str(result)

        # Return directly if short enough
        if len(result_str) <= max_chars:
            return result_str

        # Try intelligent summary for dict results
        if isinstance(result, dict):
            summary = cls._summarize_dict(result, max_chars)
            if summary:
                return summary

        # Try intelligent summary for list results
        if isinstance(result, list):
            summary = cls._summarize_list(result, max_chars)
            if summary:
                return summary

        # Fallback: simple truncation
        return cls.truncate_text(result_str, max_chars // 4)

    @classmethod
    def summarize_tool_result(cls, tool_name: str, result: Any, max_chars: int = 2200) -> str:
        """
        Intelligent summary for specific tools

        Args:
            tool_name: Tool name
            result: Tool result
            max_chars: Max characters limit

        Returns:
            Summary string
        """
        if result is None:
            return "No result"

        if not isinstance(result, dict):
            return cls.summarize_result(result, max_chars=max_chars)

        if tool_name == "disassemble_function" and isinstance(result.get("instructions"), list):
            ins = result.get("instructions") or []
            lines = []
            for item in ins[:25]:
                addr = item.get("address")
                m = item.get("mnemonic")
                op = item.get("op_str")
                if addr and m is not None:
                    lines.append(f"{addr}: {m} {op}".rstrip())
            if len(ins) > 30:
                lines.append(f"... (omitted {len(ins) - 30} instructions) ...")
                for item in ins[-5:]:
                    addr = item.get("address")
                    m = item.get("mnemonic")
                    op = item.get("op_str")
                    if addr and m is not None:
                        lines.append(f"{addr}: {m} {op}".rstrip())

            summary = {
                "function_address": result.get("function_address"),
                "instruction_count": result.get("instruction_count"),
                "instructions": lines,
            }
            return cls.summarize_result(summary, max_chars=max_chars)

        if tool_name == "analyze_taint_flow" and isinstance(result.get("paths"), list):
            paths = result.get("paths") or []
            slim = []
            for p in paths[:5]:
                slim.append({
                    "source": p.get("source"),
                    "sink": p.get("sink"),
                    "confidence": p.get("confidence"),
                    "step_count": p.get("step_count"),
                })
            summary = {
                "function": result.get("function"),
                "address": result.get("address"),
                "taint_paths_found": result.get("taint_paths_found"),
                "paths": slim,
            }
            if len(paths) > 5:
                summary["note"] = f"Showing 5 of {len(paths)} paths"
            return cls.summarize_result(summary, max_chars=max_chars)

        if tool_name == "verify_all_dangerous_imports" and isinstance(result.get("results"), list):
            items = result.get("results") or []
            items_sorted = sorted(items, key=lambda x: float(x.get("confidence_score", 0) or 0), reverse=True)
            summary = {
                "validated": result.get("validated"),
                "total": len(items),
                "top_results": items_sorted[:5],
            }
            return cls.summarize_result(summary, max_chars=max_chars)

        if tool_name == "generate_poc" and isinstance(result.get("poc_code"), str):
            code = result.get("poc_code") or ""
            slim = dict(result)
            slim["poc_code"] = f"[stored {len(code)} chars]"
            return cls.summarize_result(slim, max_chars=max_chars)

        return cls.summarize_result(result, max_chars=max_chars)

    @classmethod
    def _summarize_dict(cls, data: dict, max_chars: int) -> Optional[str]:
        """Intelligently summarize dict results"""
        # Extract key fields - ensure important fields from tools are included
        key_fields = [
            # Common fields
            'error', 'status', 'found', 'count', 'total', 'result', 'summary', 'note',
            # disassemble_function return fields
            'function_address', 'instruction_count', 'instructions',
            'is_import', 'import_api', 'import_address', 'callers', 'suggestion',
            # Vuln analysis fields
            'vulnerabilities', 'findings', 'taint_paths_found', 'paths',
            'is_likely_exploitable', 'confidence', 'risk_level',
            # Export function fields
            'exports', 'dangerous_apis', 'export_count',
            # Other analysis fields
            'source', 'sink', 'severity', 'vuln_type', 'address',
        ]

        summary = {}

        # Keep key fields
        for key in key_fields:
            if key in data:
                value = data[key]
                # If value is too large, it needs intelligent summarization
                if isinstance(value, (list, dict)):
                    value_str = json.dumps(value, ensure_ascii=False)

                    # Special handling for instructions list - keep more content for AI analysis
                    if key == 'instructions' and isinstance(value, list):
                        if len(value_str) > 2000:
                            # Show first 20 instructions
                            summary[key] = value[:20]
                            summary['_instructions_truncated'] = f"Showing first 20 of {len(value)} instructions"
                        else:
                            summary[key] = value
                    elif len(value_str) > 500:
                        if isinstance(value, list):
                            # For other lists, show more context
                            summary[key] = value[:5] if len(value) > 5 else value
                            if len(value) > 5:
                                summary[f'_{key}_note'] = f"Showing 5 of {len(value)} items"
                        else:
                            summary[key] = f"[dict with {len(value)} keys]"
                    else:
                        summary[key] = value
                else:
                    summary[key] = value

        # Add brief descriptions for other fields
        other_keys = [k for k in data.keys() if k not in key_fields]
        if other_keys:
            summary['_other_fields'] = other_keys[:10]
            if len(other_keys) > 10:
                summary['_other_fields'].append(f"... and {len(other_keys) - 10} more")

        result_str = json.dumps(summary, indent=2, ensure_ascii=False)

        if len(result_str) <= max_chars:
            return result_str
        return None

    @classmethod
    def _summarize_list(cls, data: list, max_chars: int) -> Optional[str]:
        """Intelligently summarize list results"""
        if not data:
            return "[]"

        # Show list length and first few items
        summary = {
            "total_items": len(data),
            "first_items": data[:3] if len(data) > 3 else data,
        }

        if len(data) > 3:
            summary["last_item"] = data[-1]
            summary["note"] = f"Showing 4 of {len(data)} items"

        result_str = json.dumps(summary, indent=2, ensure_ascii=False)

        if len(result_str) <= max_chars:
            return result_str
        return None
