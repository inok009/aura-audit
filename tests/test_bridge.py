"""
Unit tests for the InferenceBridge.
Uses aiohttp mocking to avoid requiring a live Ollama instance.
"""
from __future__ import annotations
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from aura_audit.inference.bridge import AuditRequest, InferenceBridge


MOCK_VALID_RESPONSE = json.dumps({
    "has_overprivilege": True,
    "severity": "HIGH",
    "findings": [
        {
            "offending_permission": "ec2:TerminateInstances",
            "reason": "Role intent is billing read-only; EC2 termination is destructive.",
            "recommendation": "Remove ec2:TerminateInstances from all attached policies."
        }
    ],
    "reasoning_summary": "The ReadOnly-Billing role has EC2 destructive permissions.",
    "confidence": 0.91
})

MOCK_MALFORMED_RESPONSE = "Here is my answer: { broken json }"


def _make_request() -> AuditRequest:
    return AuditRequest(
        principal_name="ReadOnly-Billing",
        principal_type="Role",
        semantic_intent="billing and cost visibility only, no infrastructure control",
        effective_permissions=["ce:GetCostAndUsage", "ec2:TerminateInstances"],
        cloudtrail_top_calls=["ce:GetCostAndUsage (142x)"],
        dangerous_actions_found=["ec2:TerminateInstances"],
        context_confidence=0.85,
    )


@pytest.fixture
def bridge():
    return InferenceBridge(model="qwen2.5:1.5b", ollama_url="http://localhost:11434")


class TestPromptBuilding:
    def test_prompt_contains_principal_name(self, bridge):
        req = _make_request()
        prompt = bridge._build_prompt(req)
        assert "ReadOnly-Billing" in prompt

    def test_prompt_contains_intent(self, bridge):
        req = _make_request()
        prompt = bridge._build_prompt(req)
        assert "billing and cost visibility" in prompt

    def test_prompt_contains_dangerous_action(self, bridge):
        req = _make_request()
        prompt = bridge._build_prompt(req)
        assert "ec2:TerminateInstances" in prompt


class TestResponseParsing:
    def test_valid_json_parsed(self, bridge):
        result = bridge._parse_response(MOCK_VALID_RESPONSE, "ReadOnly-Billing")
        assert result.has_overprivilege is True
        assert result.severity == "HIGH"
        assert len(result.findings) == 1
        assert result.confidence == pytest.approx(0.91)
        assert result.inference_error is None

    def test_malformed_json_returns_error(self, bridge):
        result = bridge._parse_response(MOCK_MALFORMED_RESPONSE, "ReadOnly-Billing")
        assert result.inference_error is not None
        assert "JSON_PARSE_ERROR" in result.inference_error
        assert result.has_overprivilege is False

    def test_strips_markdown_fences(self, bridge):
        fenced = f"```json\n{MOCK_VALID_RESPONSE}\n```"
        result = bridge._parse_response(fenced, "ReadOnly-Billing")
        assert result.inference_error is None
        assert result.has_overprivilege is True


@pytest.mark.asyncio
class TestAuditWithMock:
    async def test_audit_returns_result_on_success(self, bridge):
        mock_response_data = {"response": MOCK_VALID_RESPONSE}

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=mock_response_data)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.close = AsyncMock()

        bridge._session = mock_session

        result = await bridge.audit(_make_request())
        assert result.has_overprivilege is True
        assert result.severity == "HIGH"
        assert result.inference_error is None