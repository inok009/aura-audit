"""
SemanticAuditor — orchestrates the full tiered audit pipeline.

Tier 1 → HeuristicsFilter  (sync, ~0ms)
Tier 2 → ContextEngine      (sync, ~1ms)
Tier 3 → InferenceBridge    (async, ~5-30s per principal via Ollama)
"""
from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator

from ..engine.context import ContextEngine
from ..engine.heuristics import HeuristicsFilter
from ..inference.bridge import AuditRequest, InferenceBridge, InferenceResult
from ..schemas.finding import (
    Finding, FindingType, PolicyBundle, Remediation, Severity
)

logger = logging.getLogger("aura_audit.semantic_auditor")


class SemanticAuditor:
    """
    Tiered auditing orchestrator.

    fast_only=True  → runs only Tier 1+2 (no Ollama calls).
    fast_only=False → full pipeline including Tier 3 AI inference.
    """

    def __init__(
        self,
        bridge: InferenceBridge,
        fast_only: bool = False,
    ) -> None:
        self._bridge = bridge
        self._heuristics = HeuristicsFilter()
        self._context = ContextEngine()
        self._fast_only = fast_only

    async def audit_bundle(
        self, bundle: PolicyBundle
    ) -> AsyncIterator[Finding]:
        # ── Tier 1: Static Heuristics ─────────────────────────────────
        tier1_findings = list(self._heuristics.audit(bundle))
        for f in tier1_findings:
            yield f

        # ── Tier 2: Semantic Context Extraction ───────────────────────
        intent = self._context.extract(
            bundle.resource.name, bundle.resource.tags
        )
        bundle.semantic_intent = intent.intent_description

        logger.info(
            "[%s] Intent: %s (confidence=%.0f%%)",
            bundle.resource.name,
            intent.intent_description[:80],
            intent.confidence * 100,
        )

        # ── Tier 3: AI Semantic Inference ─────────────────────────────
        if self._fast_only:
            return

        request = self._build_audit_request(bundle, tier1_findings, intent)
        result = await self._bridge.audit(request)

        if result.inference_error:
            logger.warning(
                "[%s] Inference skipped: %s",
                bundle.resource.name,
                result.inference_error,
            )
            return

        async for finding in self._findings_from_inference(result, bundle):
            yield finding

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _collect_effective_permissions(self, bundle: PolicyBundle) -> list[str]:
        """Flatten all Allow'd actions across all attached policies."""
        actions: set[str] = set()
        for policy in (bundle.inline_policies + bundle.managed_policies):
            doc = policy.get("Document", policy)
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                raw = stmt.get("Action", [])
                if isinstance(raw, str):
                    raw = [raw]
                actions.update(raw)
        return sorted(actions)

    def _build_audit_request(
        self,
        bundle: PolicyBundle,
        tier1_findings: list[Finding],
        intent,
    ) -> AuditRequest:
        dangerous = [
            f.offending_statement.get("Action", "")
            for f in tier1_findings
            if f.offending_statement
            and f.finding_type in {FindingType.DANGEROUS_ACTION, FindingType.WILDCARD_ACTION}
        ]

        ct_calls = [
            f"{svc}:{action} ({count}x)"
            for svc, calls in bundle.cloudtrail_summary.items()
            for action, count in (calls.items() if isinstance(calls, dict) else {})
        ][:10]

        return AuditRequest(
            principal_name=bundle.resource.name,
            principal_type=bundle.principal_type,
            semantic_intent=intent.intent_description,
            effective_permissions=self._collect_effective_permissions(bundle),
            cloudtrail_top_calls=ct_calls,
            dangerous_actions_found=[str(d) for d in dangerous if d],
            context_confidence=intent.confidence,
        )

    async def _findings_from_inference(
        self,
        result: InferenceResult,
        bundle: PolicyBundle,
    ) -> AsyncIterator[Finding]:
        if not result.has_overprivilege:
            return

        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFORMATIONAL": Severity.INFORMATIONAL,
        }

        for ai_finding in result.findings:
            yield Finding(
                severity=severity_map.get(result.severity, Severity.MEDIUM),
                finding_type=FindingType.SEMANTIC_MISMATCH,
                title=(
                    f"Functional over-privilege: '{ai_finding.get('offending_permission')}' "
                    f"contradicts role intent"
                ),
                description=ai_finding.get("reason", ""),
                resource=bundle.resource,
                semantic_context=bundle.semantic_intent,
                ai_reasoning=result.reasoning_summary,
                remediation=Remediation(
                    recommendation=ai_finding.get("recommendation", ""),
                ),
                confidence=result.confidence,
                tier=3,
            )