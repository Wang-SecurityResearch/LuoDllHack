# -*- coding: utf-8 -*-
"""OpenAI GPT-4 client for vulnerability verification."""

import json
from dataclasses import dataclass
from typing import Optional, Callable
from PySide2.QtCore import QThread, Signal, QMutex, QWaitCondition

from ..config import config
from ..analysis.report_parser import Finding
from ..analysis.context_extractor import VerificationContext
from ..analysis.vuln_checkers import AnalysisResult
from .prompts import PromptBuilder


@dataclass
class VerificationRequest:
    """Request for AI verification"""
    finding_id: str
    finding: Finding
    context: VerificationContext
    analysis: AnalysisResult


@dataclass
class VerificationResult:
    """Result from AI verification"""
    finding_id: str
    success: bool
    verdict: str = ""              # true_positive/false_positive/inconclusive
    confidence: float = 0.0
    reasoning: str = ""
    exploitability: str = ""
    key_evidence: list = None
    mitigations_found: list = None
    error: str = ""

    def __post_init__(self):
        if self.key_evidence is None:
            self.key_evidence = []
        if self.mitigations_found is None:
            self.mitigations_found = []


class OpenAIVerifier(QThread):
    """Background thread for OpenAI verification requests"""

    # Signals
    result_ready = Signal(object)  # VerificationResult
    error_occurred = Signal(str, str)  # finding_id, error_message
    progress_update = Signal(str, str)  # finding_id, status_message

    def __init__(self, parent=None):
        super().__init__(parent)
        self._queue = []
        self._mutex = QMutex()
        self._condition = QWaitCondition()
        self._running = True
        self._client = None

    def queue_request(self, request: VerificationRequest) -> None:
        """Add verification request to queue"""
        self._mutex.lock()
        self._queue.append(request)
        self._condition.wakeOne()
        self._mutex.unlock()

    def stop(self) -> None:
        """Stop the worker thread"""
        self._running = False
        self._mutex.lock()
        self._condition.wakeAll()
        self._mutex.unlock()
        self.wait()

    def run(self) -> None:
        """Process verification queue"""
        # Initialize OpenAI client
        try:
            import openai
            self._client = openai.OpenAI(api_key=config.api_key)
        except ImportError:
            self.error_occurred.emit("", "OpenAI package not installed. Run: pip install openai")
            return
        except Exception as e:
            self.error_occurred.emit("", f"Failed to initialize OpenAI client: {e}")
            return

        while self._running:
            # Wait for requests
            self._mutex.lock()
            while self._running and not self._queue:
                self._condition.wait(self._mutex)

            if not self._running:
                self._mutex.unlock()
                break

            # Get next request
            request = self._queue.pop(0) if self._queue else None
            self._mutex.unlock()

            if request:
                self._process_request(request)

    def _process_request(self, request: VerificationRequest) -> None:
        """Process a single verification request"""
        finding_id = request.finding_id

        try:
            self.progress_update.emit(finding_id, "Building prompt...")

            # Build prompt
            prompt = PromptBuilder.build_prompt(
                request.finding,
                request.context,
                request.analysis
            )

            self.progress_update.emit(finding_id, "Calling GPT-4...")

            # Call OpenAI API
            response = self._client.chat.completions.create(
                model=config.model,
                messages=[
                    {"role": "system", "content": PromptBuilder.get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                response_format={"type": "json_object"}
            )

            # Parse response
            content = response.choices[0].message.content
            result = self._parse_response(finding_id, content)
            self.result_ready.emit(result)

        except Exception as e:
            error_msg = str(e)
            self.error_occurred.emit(finding_id, error_msg)
            self.result_ready.emit(VerificationResult(
                finding_id=finding_id,
                success=False,
                error=error_msg
            ))

    def _parse_response(self, finding_id: str, content: str) -> VerificationResult:
        """Parse AI response JSON"""
        try:
            data = json.loads(content)
            return VerificationResult(
                finding_id=finding_id,
                success=True,
                verdict=data.get("verdict", "inconclusive"),
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", ""),
                exploitability=data.get("exploitability", "unknown"),
                key_evidence=data.get("key_evidence", []),
                mitigations_found=data.get("mitigations_found", [])
            )
        except json.JSONDecodeError as e:
            return VerificationResult(
                finding_id=finding_id,
                success=False,
                error=f"Failed to parse AI response: {e}"
            )
