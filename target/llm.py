"""LLM backends: Ollama (local), Anthropic (API comparison) and the simulated
model in `target.simllm`. All expose `generate(system, user) -> str`."""
from __future__ import annotations

import os

import requests


class OllamaLLM:
    """Local models via Ollama's HTTP API. Pull first, e.g.
    `ollama pull llama3.1:8b` and `ollama pull qwen2.5:7b`."""

    def __init__(self, model: str = "llama3.1:8b", host: str | None = None, seed: int = 0, timeout: int = 300):
        self.model = model
        self.name = f"ollama:{model}"
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.seed = seed
        self.timeout = timeout

    def generate(self, system: str, user: str) -> str:
        r = requests.post(
            f"{self.host}/api/chat",
            json={"model": self.model, "stream": False,
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                  "options": {"temperature": 0, "seed": self.seed, "num_predict": 300}},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()["message"]["content"]


class AnthropicLLM:
    """Optional stronger-model comparison. Needs `pip install anthropic` and ANTHROPIC_API_KEY."""

    def __init__(self, model: str = "claude-haiku-5-5"):
        import anthropic  # lazy

        self.client = anthropic.Anthropic()
        self.model = model
        self.name = f"anthropic:{model}"

    def generate(self, system: str, user: str) -> str:
        m = self.client.messages.create(model=self.model, max_tokens=300, temperature=0, system=system,
                                        messages=[{"role": "user", "content": user}])
        return "".join(b.text for b in m.content if getattr(b, "type", "") == "text")


def get_llm(spec: str = "sim:llama-like", seed: int = 0):
    """spec: sim:<profile> | ollama:<model> | anthropic:<model>"""
    kind, _, arg = spec.partition(":")
    if kind == "sim":
        from target.simllm import SimLLM
        return SimLLM(arg or "llama-like", seed=seed)
    if kind == "ollama":
        return OllamaLLM(arg or "llama3.1:8b", seed=seed)
    if kind == "anthropic":
        return AnthropicLLM(arg or "claude-haiku-5-5")
    raise ValueError(f"unknown LLM spec {spec!r}")
