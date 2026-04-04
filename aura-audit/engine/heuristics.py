"""
Tier-1 Heuristics Filter.

Fast, zero-cost static analysis that catches the obvious issues
before any AI inference is triggered. Runs synchronously.
"""
from __future__ import annotations
import re
from typing import Iterator
from ..schemas.finding import (
    Finding, FindingType, Severity, Remediation, PolicyBundle
)

# Actions that are unambiguously dangerous regardless of resource scope
CRITICAL_ACTIONS: frozenset[str] = frozenset({
    "iam:CreateUser", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PassRole",
    "iam:CreatePolicyVersion", "sts:AssumeRole",
    "ec2:TerminateInstances", "s3:DeleteBucket",
    "organizations:DeleteOrganization", "kms:ScheduleKeyDeletion",
})

ADMIN_POLICY_ARNS: frozenset[str] = frozenset({
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
})


class HeuristicsFilter:
    """
    Runs deterministic checks on raw policy documents.
    Returns an iterator of zero-cost Finding objects.
    """

    def audit(self, bundle: PolicyBundle) -> Iterator[Finding]:
        all_statements = self._collect_statements(bundle)

        for stmt in all_statements:
            if stmt.get("Effect") != "Allow":
                continue

            yield from self._check_wildcard_action(stmt, bundle)
            yield from self._check_wildcard_resource(stmt, bundle)
            yield from self._check_not_action(stmt, bundle)
            yield from self._check_dangerous_actions(stmt, bundle)

        yield from self._check_admin_managed_policies(bundle)

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _collect_statements(self, bundle: PolicyBundle) -> list[dict]:
        stmts = []
        for policy in (
            bundle.inline_policies
            + bundle.managed_policies
            + bundle.permission_boundaries
        ):
            doc = policy.get("Document", policy)
            stmts.extend(
                doc.get("Statement", [])
                if isinstance(doc, dict)
                else []
            )
        return stmts

    def _actions_as_list(self, stmt: dict) -> list[str]:
        actions = stmt.get("Action", [])
        return actions if isinstance(actions, list) else [actions]

    def _resources_as_list(self, stmt: dict) -> list[str]:
        resources = stmt.get("Resource", [])
        return resources if isinstance(resources, list) else [resources]

    def _check_wildcard_action(
        self, stmt: dict, bundle: PolicyBundle
    ) -> Iterator[Finding]:
        for action in self._actions_as_list(stmt):
            if action == "*":
                yield Finding(
                    severity=Severity.CRITICAL,
                    finding_type=FindingType.WILDCARD_ACTION,
                    title="Wildcard action '*' grants unrestricted API access",
                    description=(
                        f"Principal '{bundle.resource.name}' has a policy "
                        f"statement granting Action: '*', which allows every "
                        f"AWS API call. This is effectively AdministratorAccess."
                    ),
                    resource=bundle.resource,
                    offending_statement=stmt,
                    remediation=Remediation(
                        recommendation=(
                            "Replace Action: '*' with the minimum set of actions "
                            "required for the role's function. Use IAM Access "
                            "Analyzer to identify actually-used permissions."
                        ),
                        reference_url=(
                            "https://docs.aws.amazon.com/IAM/latest/"
                            "UserGuide/best-practices.html"
                        ),
                    ),
                    confidence=1.0,
                    tier=1,
                )
            elif action.endswith(":*"):
                service = action.split(":")[0]
                yield Finding(
                    severity=Severity.HIGH,
                    finding_type=FindingType.WILDCARD_ACTION,
                    title=f"Service-wide wildcard '{action}' grants full {service.upper()} access",
                    description=(
                        f"Principal '{bundle.resource.name}' has '{action}', "
                        f"granting every {service} API operation."
                    ),
                    resource=bundle.resource,
                    offending_statement=stmt,
                    remediation=Remediation(
                        recommendation=f"Scope down to specific {service} actions required.",
                    ),
                    confidence=1.0,
                    tier=1,
                )

    def _check_wildcard_resource(
        self, stmt: dict, bundle: PolicyBundle
    ) -> Iterator[Finding]:
        actions = self._actions_as_list(stmt)
        resources = self._resources_as_list(stmt)
        if "*" in resources and any(
            a in CRITICAL_ACTIONS for a in actions
        ):
            yield Finding(
                severity=Severity.HIGH,
                finding_type=FindingType.WILDCARD_RESOURCE,
                title="Critical action applied to all resources ('*')",
                description=(
                    f"Actions {actions} on Resource: '*' in principal "
                    f"'{bundle.resource.name}' allow unrestricted scope."
                ),
                resource=bundle.resource,
                offending_statement=stmt,
                remediation=Remediation(
                    recommendation=(
                        "Constrain the Resource to specific ARNs or ARN patterns."
                    ),
                ),
                confidence=0.95,
                tier=1,
            )

    def _check_not_action(
        self, stmt: dict, bundle: PolicyBundle
    ) -> Iterator[Finding]:
        if "NotAction" in stmt:
            yield Finding(
                severity=Severity.MEDIUM,
                finding_type=FindingType.WILDCARD_ACTION,
                title="NotAction pattern implicitly allows broad permissions",
                description=(
                    f"Using NotAction in '{bundle.resource.name}' is a common "
                    f"misconfiguration that permits all actions *except* the listed "
                    f"ones, often granting far more than intended."
                ),
                resource=bundle.resource,
                offending_statement=stmt,
                remediation=Remediation(
                    recommendation=(
                        "Replace NotAction with an explicit Allow list. "
                        "NotAction is almost never the right construct."
                    ),
                ),
                confidence=0.90,
                tier=1,
            )

    def _check_dangerous_actions(
        self, stmt: dict, bundle: PolicyBundle
    ) -> Iterator[Finding]:
        actions = self._actions_as_list(stmt)
        for action in actions:
            if action in CRITICAL_ACTIONS:
                yield Finding(
                    severity=Severity.HIGH,
                    finding_type=FindingType.DANGEROUS_ACTION,
                    title=f"Dangerous action '{action}' explicitly allowed",
                    description=(
                        f"Principal '{bundle.resource.name}' is explicitly "
                        f"granted '{action}', which is a high-impact operation."
                    ),
                    resource=bundle.resource,
                    offending_statement=stmt,
                    remediation=Remediation(
                        recommendation=(
                            f"Verify '{action}' is strictly required. "
                            f"If needed, constrain via Condition keys."
                        ),
                    ),
                    confidence=0.85,
                    tier=1,
                )

    def _check_admin_managed_policies(
        self, bundle: PolicyBundle
    ) -> Iterator[Finding]:
        for policy in bundle.managed_policies:
            arn = policy.get("PolicyArn", "")
            if arn in ADMIN_POLICY_ARNS:
                yield Finding(
                    severity=Severity.CRITICAL,
                    finding_type=FindingType.ADMIN_POLICY,
                    title=f"AWS-managed admin policy '{arn}' attached",
                    description=(
                        f"Principal '{bundle.resource.name}' has the AWS-managed "
                        f"policy '{arn}' attached. This grants unrestricted access "
                        f"to all AWS services and resources."
                    ),
                    resource=bundle.resource,
                    remediation=Remediation(
                        recommendation=(
                            "Detach and replace with a least-privilege custom policy "
                            "scoped to the role's actual function."
                        ),
                    ),
                    confidence=1.0,
                    tier=1,
                )