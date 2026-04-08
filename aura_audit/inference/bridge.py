"""
Inference Bridge — Async wrapper for the local Ollama API.

Design goals:
  - Never block the main thread (fully async).
  - Never contact external APIs. Local Ollama only.
  - Structured prompt engineering for IAM audit reasoning.
  - Configurable concurrency via asyncio.Semaphore.
  - Graceful degradation: if Ollama is unreachable, findings
    are tagged as INFERENCE_UNAVAILABLE and processing continues.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import aiohttp

logger = logging.getLogger("aura_audit.inference")

_SYSTEM_PROMPT = """\
You are an expert AWS IAM security auditor. You will be given:
1. The SEMANTIC INTENT of an IAM principal (what this role/user is SUPPOSED to do).
2. The EFFECTIVE PERMISSIONS granted by its policies.
3. Recent CloudTrail usage data.

Your task: identify FUNCTIONAL OVER-PRIVILEGE — permissions that contradict the
principal's stated purpose. Be precise and actionable.

Respond ONLY with a valid JSON object matching this exact schema:
{
  "has_overprivilege": boolean,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
  "findings": [
    {
      "offending_permission": "<service>:<Action>",
      "reason": "<one sentence explaining why this contradicts the intent>",
      "recommendation": "<specific remediation step>"
    }
  ],
  "reasoning_summary": "<2-3 sentence overall assessment>",
  "confidence": <float 0.0–1.0>
}

Do not include markdown, code fences, or commentary. Pure JSON only.
"""


@dataclass
class AuditRequest:
    """Structured payload sent to the local SLM."""
    principal_name: str
    principal_type: str
    semantic_intent: str
    effective_permissions: list[str]          # flattened action strings
    cloudtrail_top_calls: list[str]           # top 10 API calls in last 30d
    dangerous_actions_found: list[str] = field(default_factory=list)
    context_confidence: float = 0.5


@dataclass
class InferenceResult:
    """Parsed response from the SLM."""
    principal_name: str
    has_overprivilege: bool
    severity: str
    findings: list[dict[str, str]]
    reasoning_summary: str
    confidence: float
    raw_response: str = ""
    inference_error: str | None = None


class InferenceBridge:
    """
    Async, non-blocking wrapper around the Ollama /api/generate endpoint.

    Usage:
        bridge = InferenceBridge(model="qwen2.5:1.5b", concurrency=1)
        async with bridge:
            result = await bridge.audit(request)
    """

    def __init__(
        self,
        model: str = "qwen2.5:1.5b",
        ollama_url: str = "http://localhost:11434",
        concurrency: int = 1,
        timeout_seconds: int = 120,
    ) -> None:
        self.model = model
        self.base_url = ollama_url.rstrip("/")
        self._semaphore = asyncio.Semaphore(concurrency)
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "InferenceBridge":
        self._session = aiohttp.ClientSession(timeout=self._timeout)
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session:
            await self._session.close()

    # ------------------------------------------------------------------ #
    #  Public interface                                                    #
    # ------------------------------------------------------------------ #

    async def audit(self, request: AuditRequest) -> InferenceResult:
        """
        Send one AuditRequest to the SLM and parse the JSON response.
        Respects the concurrency semaphore to avoid overwhelming Ollama.
        """
        async with self._semaphore:
            prompt = self._build_prompt(request)
            logger.debug(
                "Sending inference request for '%s'", request.principal_name
            )

            try:
                raw = await self._call_ollama(prompt)
                return self._parse_response(raw, request.principal_name)
            except aiohttp.ClientConnectorError:
                logger.warning(
                    "Ollama unreachable at %s — skipping AI tier for '%s'",
                    self.base_url,
                    request.principal_name,
                )
                return InferenceResult(
                    principal_name=request.principal_name,
                    has_overprivilege=False,
                    severity="INFORMATIONAL",
                    findings=[],
                    reasoning_summary="",
                    confidence=0.0,
                    inference_error="OLLAMA_UNREACHABLE",
                )
            except Exception as exc:
                logger.error(
                    "Inference failed for '%s': %s",
                    request.principal_name,
                    exc,
                )
                return InferenceResult(
                    principal_name=request.principal_name,
                    has_overprivilege=False,
                    severity="INFORMATIONAL",
                    findings=[],
                    reasoning_summary="",
                    confidence=0.0,
                    inference_error=str(exc),
                )

    async def health_check(self) -> bool:
        """Verify Ollama is up and the target model is available."""
        try:
            async with self._session.get(f"{self.base_url}/api/tags") as resp:
                if resp.status != 200:
                    return False
                data = await resp.json()
                model_names = [m["name"] for m in data.get("models", [])]
                available = any(
                    self.model in name for name in model_names
                )
                if not available:
                    logger.warning(
                        "Model '%s' not found in Ollama. Available: %s",
                        self.model,
                        model_names,
                    )
                return available
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _build_prompt(self, request: AuditRequest) -> str:
        perms_block = "\n".join(f"  - {p}" for p in request.effective_permissions[:15])
        ct_block = (
            "\n".join(f"  - {c}" for c in request.cloudtrail_top_calls)
            if request.cloudtrail_top_calls
            else "  (no CloudTrail data available)"
        )
        dangerous_block = (
            "\n".join(f"  - {d}" for d in request.dangerous_actions_found)
            if request.dangerous_actions_found
            else "  (none flagged by static analysis)"
        )

        return (
            f"PRINCIPAL: {request.principal_name} ({request.principal_type})\n\n"
            f"SEMANTIC INTENT (inferred from name/tags):\n"
            f"  {request.semantic_intent}\n"
            f"  Intent confidence: {request.context_confidence:.0%}\n\n"
            f"EFFECTIVE PERMISSIONS (sample, up to 15):\n{perms_block}\n\n"
            f"CLOUDTRAIL — TOP API CALLS (last 30 days):\n{ct_block}\n\n"
            f"PRE-FLAGGED DANGEROUS ACTIONS (from static analysis):\n{dangerous_block}\n\n"
            f"Identify functional over-privilege. Respond with the JSON schema only."
        )

    async def _call_ollama(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": _SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 400,
                "num_ctx": 1024,
            },
        }

        async with self._session.post(
            f"{self.base_url}/api/generate",
            json=payload,
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data.get("response", "")

    def _parse_response(self, raw: str, principal_name: str) -> InferenceResult:
        """
        Robustly parse the SLM JSON output.
        Strips any accidental markdown fences before parsing.
        Attempts recovery on truncated JSON before discarding.
        """
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = "\n".join(
                line for line in cleaned.splitlines()
                if not line.strip().startswith("```")
            ).strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            recovered = self._attempt_json_recovery(cleaned)
            if recovered:
                logger.debug("Recovered truncated JSON for '%s'", principal_name)
                data = recovered
            else:
                logger.debug(
                    "Raw model output for '%s' (first 500 chars): %.500s",
                    principal_name,
                    raw,
                )
                return InferenceResult(
                    principal_name=principal_name,
                    has_overprivilege=False,
                    severity="INFORMATIONAL",
                    findings=[],
                    reasoning_summary="",
                    confidence=0.0,
                    raw_response=raw,
                    inference_error="JSON_PARSE_ERROR: truncated response",
                )

        return InferenceResult(
            principal_name=principal_name,
            has_overprivilege=data.get("has_overprivilege", False),
            severity=data.get("severity", "INFORMATIONAL"),
            findings=data.get("findings", []),
            reasoning_summary=data.get("reasoning_summary", ""),
            confidence=float(data.get("confidence", 0.5)),
            raw_response=raw,
        )

    def _attempt_json_recovery(self, text: str) -> dict | None:
        """Try to recover a truncated JSON object by trimming to the last valid closing brace."""
        for i in range(len(text), 0, -1):
            if text[i - 1] == "}":
                try:
                    return json.loads(text[:i])
                except json.JSONDecodeError:
                    continue
        return None