# -*- coding: utf-8 -*-
"""
luodllhack/ai/agents/llm_backend.py
LLM backend abstract layer - Supports multiple LLM providers

Supported backends:
    - GeminiBackend: Google Gemini API
    - OpenAIBackend: OpenAI GPT API
    - OllamaBackend: Local Ollama
    - AnthropicBackend: Anthropic Claude API
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Union
from enum import Enum
import time
import json
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Data structures
# =============================================================================

class BackendType(str, Enum):
    """LLM backend type"""
    GEMINI = "gemini"
    OPENAI = "openai"
    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"


@dataclass
class ToolCall:
    """Tool call"""
    name: str
    arguments: Dict[str, Any]
    call_id: Optional[str] = None


@dataclass
class LLMResponse:
    """
    Unified LLM response format

    Returns the same format regardless of backend
    """
    text: Optional[str] = None        # Text response
    tool_calls: List[ToolCall] = field(default_factory=list)  # Tool call
    finish_reason: str = "stop"       # Finish reason
    usage: Dict[str, int] = field(default_factory=dict)  # Token usage
    raw_response: Any = None          # Raw response (for debugging)
    error: Optional[str] = None       # Error message
    latency: float = 0.0              # Response latency (seconds)

    @property
    def has_tool_calls(self) -> bool:
        """Whether there is a tool call"""
        return len(self.tool_calls) > 0

    @property
    def is_error(self) -> bool:
        """Whether there is an error"""
        return self.error is not None


@dataclass
class Message:
    """Dialogue message"""
    role: str                         # user, assistant, system
    content: str
    tool_calls: List[ToolCall] = field(default_factory=list)
    tool_call_id: Optional[str] = None  # Call ID for tool response


# =============================================================================
# LLM backend abstract base class
# =============================================================================

class LLMBackend(ABC):
    """
    LLM backend abstract base class

    All LLM backends must implement:
        - generate: Single-turn generation
        - chat: Multi-turn dialogue
    """

    def __init__(
        self,
        model: str,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        timeout: float = 120.0
    ):
        """
        Initialize backend

        Args:
            model: Model name
            temperature: Sampling temperature
            max_tokens: Maximum output tokens
            timeout: Request timeout (seconds)
        """
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._initialized = False

    @property
    @abstractmethod
    def backend_type(self) -> BackendType:
        """Returns the backend type"""
        pass

    @abstractmethod
    def generate(
        self,
        prompt: str,
        tools: List[Dict] = None,
        system_prompt: str = None
    ) -> LLMResponse:
        """
        Single-turn generation

        Args:
            prompt: User prompt
            tools: Tool definitions (optional)
            system_prompt: System prompt (optional)

        Returns:
            LLM response
        """
        pass

    @abstractmethod
    def chat(
        self,
        messages: List[Message],
        tools: List[Dict] = None
    ) -> LLMResponse:
        """
        Multi-turn dialogue

        Args:
            messages: Message history
            tools: Tool definitions (optional)

        Returns:
            LLM response
        """
        pass

    def is_available(self) -> bool:
        """Checks if the backend is available"""
        return self._initialized


# =============================================================================
# Gemini backend
# =============================================================================

class GeminiBackend(LLMBackend):
    """
    Google Gemini API backend

    Uses google-generativeai library
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.5-flash",
        temperature: float = 0.1,
        max_tokens: int = 8192,
        timeout: float = 120.0
    ):
        super().__init__(model, temperature, max_tokens, timeout)
        self.api_key = api_key
        self._client = None
        self._model = None

        self._initialize()

    def _initialize(self):
        """Initialize Gemini client"""
        try:
            import google.generativeai as genai

            genai.configure(api_key=self.api_key)
            self._client = genai
            self._model = genai.GenerativeModel(
                self.model,
                generation_config=genai.GenerationConfig(
                    temperature=self.temperature,
                    max_output_tokens=self.max_tokens
                )
            )
            self._initialized = True
            logger.info(f"GeminiBackend initialized with model {self.model}")

        except ImportError:
            logger.error("google-generativeai not installed")
            self._initialized = False
        except Exception as e:
            logger.error(f"Failed to initialize GeminiBackend: {e}")
            self._initialized = False

    @property
    def backend_type(self) -> BackendType:
        return BackendType.GEMINI

    def generate(
        self,
        prompt: str,
        tools: List[Dict] = None,
        system_prompt: str = None
    ) -> LLMResponse:
        if not self._initialized:
            return LLMResponse(error="Backend not initialized")

        start_time = time.time()

        try:
            # Build complete prompt
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"

            # Configure tools
            if tools:
                model = self._client.GenerativeModel(
                    self.model,
                    tools=[{"function_declarations": tools}],
                    generation_config=self._client.GenerationConfig(
                        temperature=self.temperature,
                        max_output_tokens=self.max_tokens
                    )
                )
            else:
                model = self._model

            # Generate response
            response = model.generate_content(full_prompt)

            return self._parse_gemini_response(response, time.time() - start_time)

        except Exception as e:
            return LLMResponse(
                error=str(e),
                latency=time.time() - start_time
            )

    def chat(
        self,
        messages: List[Message],
        tools: List[Dict] = None
    ) -> LLMResponse:
        if not self._initialized:
            return LLMResponse(error="Backend not initialized")

        start_time = time.time()

        try:
            # Configure tools
            if tools:
                model = self._client.GenerativeModel(
                    self.model,
                    tools=[{"function_declarations": tools}],
                    generation_config=self._client.GenerationConfig(
                        temperature=self.temperature,
                        max_output_tokens=self.max_tokens
                    )
                )
            else:
                model = self._model

            # Create chat session
            chat = model.start_chat(history=[])

            # Send all messages (Gemini does not support passing history directly)
            response = None
            for msg in messages:
                if msg.role == "user":
                    response = chat.send_message(msg.content)

            if response is None:
                return LLMResponse(error="No user message in chat history")

            return self._parse_gemini_response(response, time.time() - start_time)

        except Exception as e:
            return LLMResponse(
                error=str(e),
                latency=time.time() - start_time
            )

    def _parse_gemini_response(self, response, latency: float) -> LLMResponse:
        """Parse Gemini response"""
        text = None
        tool_calls = []

        try:
            if response.candidates and response.candidates[0].content.parts:
                for part in response.candidates[0].content.parts:
                    if hasattr(part, 'text') and part.text:
                        text = part.text
                    if hasattr(part, 'function_call') and part.function_call:
                        fc = part.function_call
                        args = {}
                        if fc.args:
                            for key, value in fc.args.items():
                                args[key] = value
                        tool_calls.append(ToolCall(
                            name=fc.name,
                            arguments=args
                        ))

            return LLMResponse(
                text=text,
                tool_calls=tool_calls,
                finish_reason="stop",
                raw_response=response,
                latency=latency
            )

        except Exception as e:
            return LLMResponse(
                error=f"Failed to parse response: {e}",
                raw_response=response,
                latency=latency
            )


# =============================================================================
# OpenAI backend
# =============================================================================

class OpenAIBackend(LLMBackend):
    """
    OpenAI GPT API backend

    Uses openai library
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4",
        temperature: float = 0.1,
        max_tokens: int = 8192,
        base_url: str = None,
        timeout: float = 120.0
    ):
        super().__init__(model, temperature, max_tokens, timeout)
        self.api_key = api_key
        self.base_url = base_url
        self._client = None

        self._initialize()

    def _initialize(self):
        """Initialize OpenAI client"""
        try:
            from openai import OpenAI
            import httpx

            # Create custom httpx client, configure robust connection parameters
            # This is important for reusing client across threads in pool
            http_client = httpx.Client(
                timeout=httpx.Timeout(
                    connect=30.0,     # Connection timeout
                    read=120.0,       # Read timeout
                    write=30.0,       # Write timeout
                    pool=10.0,        # Get connection timeout from pool
                ),
                limits=httpx.Limits(
                    max_connections=10,           # Max connections
                    max_keepalive_connections=5,  # Max keepalive connections
                    keepalive_expiry=30.0,        # Keepalive expiry time (seconds)
                ),
                # Explicitly trust proxy settings in environment variables
                trust_env=True,
            )

            kwargs = {
                "api_key": self.api_key,
                "timeout": self.timeout,
                "http_client": http_client,
            }
            if self.base_url:
                kwargs["base_url"] = self.base_url

            self._client = OpenAI(**kwargs)
            self._initialized = True
            safe_key = f"{self.api_key[:4]}..." if self.api_key else "None"
            logger.info(f"OpenAIBackend initialized: model={self.model}, base_url={self.base_url}, api_key={safe_key}")

        except ImportError:
            logger.error("openai not installed")
            self._initialized = False
        except Exception as e:
            logger.error(f"Failed to initialize OpenAIBackend: {e}")
            self._initialized = False

    @property
    def backend_type(self) -> BackendType:
        return BackendType.OPENAI

    def generate(
        self,
        prompt: str,
        tools: List[Dict] = None,
        system_prompt: str = None
    ) -> LLMResponse:
        messages = []
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        messages.append(Message(role="user", content=prompt))

        return self.chat(messages, tools)

    def chat(
        self,
        messages: List[Message],
        tools: List[Dict] = None
    ) -> LLMResponse:
        if not self._initialized:
            return LLMResponse(error="Backend not initialized")

        start_time = time.time()

        try:
            # Convert message format
            openai_messages = []
            for msg in messages:
                openai_msg = {"role": msg.role, "content": msg.content}
                if msg.tool_call_id:
                    openai_msg["tool_call_id"] = msg.tool_call_id
                openai_messages.append(openai_msg)

            # Build request parameters
            kwargs = {
                "model": self.model,
                "messages": openai_messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
            }

            # Add tools
            if tools:
                openai_tools = [
                    {
                        "type": "function",
                        "function": {
                            "name": t["name"],
                            "description": t.get("description", ""),
                            "parameters": t.get("parameters", {})
                        }
                    }
                    for t in tools
                ]
                kwargs["tools"] = openai_tools

            # Call API
            logger.info(f"Calling OpenAI API: model={self.model}, base_url={self.base_url}")
            
            try:
                response = self._client.chat.completions.create(**kwargs)
            except Exception as e:
                # Catch connection errors and provide more context
                if "APIConnectionError" in type(e).__name__:
                    logger.error(f"OpenAI API Connection Error. Target: {self.base_url or 'Default OpenAI URL'}")
                    logger.error(f"Please check your network, proxy settings, and API base_url configuration.")
                
                logger.error(f"OpenAI API call failed: {type(e).__name__}: {e}")
                # Rethrow exception for upper layer processing (or return error response)
                # Returning error response to maintain interface consistency here
                return LLMResponse(
                    error=f"{type(e).__name__}: {e}",
                    latency=time.time() - start_time
                )

            return self._parse_openai_response(response, time.time() - start_time)

        except Exception as e:
            logger.error(f"OpenAI API call failed: {type(e).__name__}: {e}")
            return LLMResponse(
                error=f"{type(e).__name__}: {e}",
                latency=time.time() - start_time
            )

    def _parse_openai_response(self, response, latency: float) -> LLMResponse:
        """Parse OpenAI response"""
        try:
            choice = response.choices[0]
            message = choice.message

            text = message.content
            tool_calls = []

            if message.tool_calls:
                for tc in message.tool_calls:
                    args = {}
                    if tc.function.arguments:
                        try:
                            args = json.loads(tc.function.arguments)
                        except json.JSONDecodeError:
                            args = {"raw": tc.function.arguments}

                    tool_calls.append(ToolCall(
                        name=tc.function.name,
                        arguments=args,
                        call_id=tc.id
                    ))

            usage = {}
            if response.usage:
                usage = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                }

            return LLMResponse(
                text=text,
                tool_calls=tool_calls,
                finish_reason=choice.finish_reason,
                usage=usage,
                raw_response=response,
                latency=latency
            )

        except Exception as e:
            return LLMResponse(
                error=f"Failed to parse response: {e}",
                raw_response=response,
                latency=latency
            )


# =============================================================================
# Ollama backend
# =============================================================================

class OllamaBackend(LLMBackend):
    """
    Ollama local model backend

    Supports locally deployed open-source models
    """

    def __init__(
        self,
        model: str = "llama3",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.1,
        max_tokens: int = 8192,
        timeout: float = 120.0
    ):
        super().__init__(model, temperature, max_tokens, timeout)
        self.base_url = base_url.rstrip("/")
        self._client = None

        self._initialize()

    def _initialize(self):
        """Initialize Ollama client"""
        try:
            import requests

            # Checks if Ollama service is available
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                self._client = requests
                self._initialized = True
                logger.info(f"OllamaBackend initialized with model {self.model}")
            else:
                logger.error(f"Ollama service not available: {response.status_code}")
                self._initialized = False

        except ImportError:
            logger.error("requests not installed")
            self._initialized = False
        except Exception as e:
            logger.error(f"Failed to initialize OllamaBackend: {e}")
            self._initialized = False

    @property
    def backend_type(self) -> BackendType:
        return BackendType.OLLAMA

    def generate(
        self,
        prompt: str,
        tools: List[Dict] = None,
        system_prompt: str = None
    ) -> LLMResponse:
        if not self._initialized:
            return LLMResponse(error="Backend not initialized")

        start_time = time.time()

        try:
            # Build request
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens
                }
            }

            if system_prompt:
                payload["system"] = system_prompt

            # Ollama tool support is limited, simplified handling here
            if tools:
                tools_desc = "\n".join([
                    f"- {t['name']}: {t.get('description', '')}"
                    for t in tools
                ])
                payload["prompt"] = f"Available tools:\n{tools_desc}\n\n{prompt}"

            response = self._client.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()

            return LLMResponse(
                text=data.get("response", ""),
                finish_reason="stop" if data.get("done") else "length",
                usage={
                    "prompt_tokens": data.get("prompt_eval_count", 0),
                    "completion_tokens": data.get("eval_count", 0)
                },
                raw_response=data,
                latency=time.time() - start_time
            )

        except Exception as e:
            return LLMResponse(
                error=str(e),
                latency=time.time() - start_time
            )

    def chat(
        self,
        messages: List[Message],
        tools: List[Dict] = None
    ) -> LLMResponse:
        if not self._initialized:
            return LLMResponse(error="Backend not initialized")

        start_time = time.time()

        try:
            # Convert message format
            ollama_messages = [
                {"role": msg.role, "content": msg.content}
                for msg in messages
            ]

            payload = {
                "model": self.model,
                "messages": ollama_messages,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens
                }
            }

            response = self._client.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()

            return LLMResponse(
                text=data.get("message", {}).get("content", ""),
                finish_reason="stop" if data.get("done") else "length",
                raw_response=data,
                latency=time.time() - start_time
            )

        except Exception as e:
            return LLMResponse(
                error=str(e),
                latency=time.time() - start_time
            )


# =============================================================================
# Anthropic backend
# =============================================================================

class AnthropicBackend(LLMBackend):
    """
    Anthropic Claude API backend

    Uses anthropic library
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-opus-20240229",
        temperature: float = 0.1,
        max_tokens: int = 8192,
        timeout: float = 120.0
    ):
        super().__init__(model, temperature, max_tokens, timeout)
        self.api_key = api_key
        self._client = None

        self._initialize()

    def _initialize(self):
        """Initialize Anthropic client"""
        try:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self.api_key)
            self._initialized = True
            logger.info(f"AnthropicBackend initialized with model {self.model}")

        except ImportError:
            logger.error("anthropic not installed")
            self._initialized = False
        except Exception as e:
            logger.error(f"Failed to initialize AnthropicBackend: {e}")
            self._initialized = False

    @property
    def backend_type(self) -> BackendType:
        return BackendType.ANTHROPIC

    def generate(
        self,
        prompt: str,
        tools: List[Dict] = None,
        system_prompt: str = None
    ) -> LLMResponse:
        messages = [Message(role="user", content=prompt)]
        return self._call_api(messages, tools, system_prompt)

    def chat(
        self,
        messages: List[Message],
        tools: List[Dict] = None
    ) -> LLMResponse:
        # Extract system prompt
        system_prompt = None
        chat_messages = []
        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                chat_messages.append(msg)

        return self._call_api(chat_messages, tools, system_prompt)

    def _call_api(
        self,
        messages: List[Message],
        tools: List[Dict] = None,
        system_prompt: str = None
    ) -> LLMResponse:
        if not self._initialized:
            return LLMResponse(error="Backend not initialized")

        start_time = time.time()

        try:
            # Convert message format
            anthropic_messages = [
                {"role": msg.role, "content": msg.content}
                for msg in messages
            ]

            kwargs = {
                "model": self.model,
                "messages": anthropic_messages,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
            }

            if system_prompt:
                kwargs["system"] = system_prompt

            # Add tools
            if tools:
                anthropic_tools = [
                    {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "input_schema": t.get("parameters", {})
                    }
                    for t in tools
                ]
                kwargs["tools"] = anthropic_tools

            response = self._client.messages.create(**kwargs)

            return self._parse_anthropic_response(response, time.time() - start_time)

        except Exception as e:
            return LLMResponse(
                error=str(e),
                latency=time.time() - start_time
            )

    def _parse_anthropic_response(self, response, latency: float) -> LLMResponse:
        """Parse Anthropic response"""
        try:
            text = None
            tool_calls = []

            for block in response.content:
                if block.type == "text":
                    text = block.text
                elif block.type == "tool_use":
                    tool_calls.append(ToolCall(
                        name=block.name,
                        arguments=block.input,
                        call_id=block.id
                    ))

            usage = {}
            if response.usage:
                usage = {
                    "prompt_tokens": response.usage.input_tokens,
                    "completion_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.input_tokens + response.usage.output_tokens
                }

            return LLMResponse(
                text=text,
                tool_calls=tool_calls,
                finish_reason=response.stop_reason,
                usage=usage,
                raw_response=response,
                latency=latency
            )

        except Exception as e:
            return LLMResponse(
                error=f"Failed to parse response: {e}",
                raw_response=response,
                latency=latency
            )


# =============================================================================
# Factory function
# =============================================================================

def create_backend(
    backend_type: Union[str, BackendType],
    **kwargs
) -> Optional[LLMBackend]:
    """
    Create LLMBackend instance

    Args:
        backend_type: Backend type
        **kwargs: Backend specific parameters

    Returns:
        LLMBackend instance, returns None on failure

    Example:
        # Gemini
        backend = create_backend("gemini", api_key="...")

        # OpenAI
        backend = create_backend("openai", api_key="...", model="gpt-4")

        # Ollama
        backend = create_backend("ollama", model="llama3")

        # Anthropic
        backend = create_backend("anthropic", api_key="...", model="claude-3-opus-20240229")
    """
    if isinstance(backend_type, str):
        backend_type = BackendType(backend_type.lower())

    try:
        if backend_type == BackendType.GEMINI:
            return GeminiBackend(**kwargs)
        elif backend_type == BackendType.OPENAI:
            return OpenAIBackend(**kwargs)
        elif backend_type == BackendType.OLLAMA:
            return OllamaBackend(**kwargs)
        elif backend_type == BackendType.ANTHROPIC:
            return AnthropicBackend(**kwargs)
        else:
            logger.error(f"Unknown backend type: {backend_type}")
            return None

    except Exception as e:
        logger.error(f"Failed to create backend {backend_type}: {e}")
        return None


def create_backend_from_config(config: Any) -> Optional[LLMBackend]:
    """
    Create backend from config object

    Args:
        config: LuoDllHackConfig object

    Returns:
        LLMBackend instance
    """
    backend_type = getattr(config, "ai_backend", "gemini")

    if backend_type == "gemini":
        return create_backend(
            "gemini",
            api_key=getattr(config, "ai_api_key", None) or "",
            model=getattr(config, "ai_model", "gemini-2.5-flash"),
            temperature=getattr(config, "ai_temperature", 0.1),
            max_tokens=getattr(config, "ai_max_tokens", 8192)
        )

    elif backend_type == "openai":
        return create_backend(
            "openai",
            api_key=getattr(config, "ai_openai_api_key", None) or "",
            model=getattr(config, "ai_openai_model", "gpt-4"),
            base_url=getattr(config, "ai_openai_base_url", None),
            temperature=getattr(config, "ai_temperature", 0.1),
            max_tokens=getattr(config, "ai_max_tokens", 8192)
        )

    elif backend_type == "ollama":
        return create_backend(
            "ollama",
            model=getattr(config, "ai_ollama_model", "llama3"),
            base_url=getattr(config, "ai_ollama_base_url", "http://localhost:11434"),
            temperature=getattr(config, "ai_temperature", 0.1),
            max_tokens=getattr(config, "ai_max_tokens", 8192)
        )

    elif backend_type == "anthropic":
        return create_backend(
            "anthropic",
            api_key=getattr(config, "ai_anthropic_api_key", None) or "",
            model=getattr(config, "ai_anthropic_model", "claude-3-opus-20240229"),
            temperature=getattr(config, "ai_temperature", 0.1),
            max_tokens=getattr(config, "ai_max_tokens", 8192)
        )

    else:
        logger.error(f"Unknown backend type in config: {backend_type}")
        return None
