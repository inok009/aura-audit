"""Unit tests for the ContextEngine."""
import pytest
from aura_audit.engine.context import ContextEngine


class TestContextEngine:
    def setup_method(self):
        self.engine = ContextEngine()

    def test_billing_role_detected(self):
        intent = self.engine.extract(
            "ReadOnly-Billing", {"Team": "FinOps", "Purpose": "cost-reporting"}
        )
        assert "billing" in intent.intent_description.lower()
        assert intent.confidence >= 0.5

    def test_deploy_role_detected(self):
        intent = self.engine.extract(
            "CICD-Deploy-Role", {"Purpose": "pipeline"}
        )
        assert "deploy" in intent.intent_description.lower()

    def test_unknown_role_low_confidence(self):
        intent = self.engine.extract("xyz-abc-123", {})
        assert intent.confidence < 0.4

    def test_multiple_keywords_compound(self):
        intent = self.engine.extract(
            "ReadOnly-Billing-Auditor",
            {"Purpose": "cost-reporting and compliance"}
        )
        # Should match both read-only and billing patterns
        assert intent.confidence >= 0.6

    def test_lambda_exec_detected(self):
        intent = self.engine.extract(
            "Lambda-Exec-DataProcessor",
            {"Team": "DataEng"}
        )
        assert "lambda" in intent.intent_description.lower()