"""Unit tests for the Tier-1 HeuristicsFilter."""
import pytest
from aura_audit.engine.heuristics import HeuristicsFilter
from aura_audit.schemas.finding import (
    FindingType, PolicyBundle, Resource, Severity
)


def _make_bundle(statements: list[dict], managed: list[dict] | None = None) -> PolicyBundle:
    return PolicyBundle(
        principal_id="AROATEST001",
        principal_type="Role",
        resource=Resource(
            type="AwsIamRole",
            id="arn:aws:iam::123456789012:role/TestRole",
            name="TestRole",
        ),
        inline_policies=[
            {"PolicyName": "TestPolicy",
             "Document": {"Version": "2012-10-17", "Statement": statements}}
        ],
        managed_policies=managed or [],
    )


class TestWildcardAction:
    def test_star_action_is_critical(self):
        bundle = _make_bundle([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        findings = list(HeuristicsFilter().audit(bundle))
        assert any(
            f.finding_type == FindingType.WILDCARD_ACTION
            and f.severity == Severity.CRITICAL
            for f in findings
        )

    def test_service_wildcard_is_high(self):
        bundle = _make_bundle([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
        findings = list(HeuristicsFilter().audit(bundle))
        assert any(
            f.finding_type == FindingType.WILDCARD_ACTION
            and f.severity == Severity.HIGH
            for f in findings
        )

    def test_deny_effect_ignored(self):
        bundle = _make_bundle([{"Effect": "Deny", "Action": "*", "Resource": "*"}])
        findings = list(HeuristicsFilter().audit(bundle))
        assert len(findings) == 0


class TestNotAction:
    def test_not_action_flagged(self):
        bundle = _make_bundle([
            {"Effect": "Allow", "NotAction": ["s3:GetObject"], "Resource": "*"}
        ])
        findings = list(HeuristicsFilter().audit(bundle))
        assert any(f.finding_type == FindingType.WILDCARD_ACTION for f in findings)


class TestDangerousActions:
    def test_terminate_instances_flagged(self):
        bundle = _make_bundle([
            {"Effect": "Allow", "Action": ["ec2:TerminateInstances"], "Resource": "*"}
        ])
        findings = list(HeuristicsFilter().audit(bundle))
        assert any(f.finding_type == FindingType.DANGEROUS_ACTION for f in findings)


class TestAdminPolicy:
    def test_administrator_access_critical(self):
        bundle = _make_bundle(
            statements=[],
            managed=[{
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "Document": {},
            }],
        )
        findings = list(HeuristicsFilter().audit(bundle))
        assert any(
            f.finding_type == FindingType.ADMIN_POLICY
            and f.severity == Severity.CRITICAL
            for f in findings
        )