"""
AWS Ingestion Module.

Fetches IAM policies, metadata, tags, and CloudTrail summaries
via Boto3. All network calls are wrapped in asyncio.to_thread
so the event loop is never blocked.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ...schemas.finding import PolicyBundle, Resource
from .models import CloudTrailSummary, GroupMetadata, RoleMetadata, UserMetadata

logger = logging.getLogger("aura_audit.ingestion")


class AWSIngestion:
    def __init__(
        self,
        session: boto3.Session,
        region: str,
        endpoint_url: str | None = None,
    ) -> None:
        self._session = session
        self._region = region
        # Conditionally pass endpoint_url for LocalStack / custom endpoints
        kw = {"endpoint_url": endpoint_url} if endpoint_url else {}
        self._iam = session.client("iam", **kw)
        self._cloudtrail = session.client("cloudtrail", region_name=region, **kw)

    # ── Principals ────────────────────────────────────────────────────

    async def list_roles(self) -> list[RoleMetadata]:
        return await asyncio.to_thread(self._list_roles_sync)

    def _list_roles_sync(self) -> list[RoleMetadata]:
        roles = []
        paginator = self._iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page["Roles"]:
                tags = self._get_role_tags(r["RoleName"])
                roles.append(RoleMetadata(
                    role_id=r["RoleId"],
                    role_name=r["RoleName"],
                    arn=r["Arn"],
                    path=r["Path"],
                    tags=tags,
                    description=r.get("Description", ""),
                    max_session_duration=r.get("MaxSessionDuration", 3600),
                ))
        logger.info("Discovered %d roles", len(roles))
        return roles

    async def list_users(self) -> list[UserMetadata]:
        return await asyncio.to_thread(self._list_users_sync)

    def _list_users_sync(self) -> list[UserMetadata]:
        users = []
        paginator = self._iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                tags = {
                    t["Key"]: t["Value"]
                    for t in self._iam.list_user_tags(UserName=u["UserName"])
                    .get("Tags", [])
                }
                users.append(UserMetadata(
                    user_id=u["UserId"],
                    user_name=u["UserName"],
                    arn=u["Arn"],
                    path=u["Path"],
                    tags=tags,
                ))
        return users

    async def list_groups(self) -> list[GroupMetadata]:
        return await asyncio.to_thread(self._list_groups_sync)

    def _list_groups_sync(self) -> list[GroupMetadata]:
        groups = []
        paginator = self._iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page["Groups"]:
                groups.append(GroupMetadata(
                    group_id=g["GroupId"],
                    group_name=g["GroupName"],
                    arn=g["Arn"],
                    path=g["Path"],
                ))
        return groups

    # ── Policy fetching ───────────────────────────────────────────────

    async def fetch_role_bundle(self, role: RoleMetadata) -> PolicyBundle:
        return await asyncio.to_thread(self._fetch_role_bundle_sync, role)

    def _fetch_role_bundle_sync(self, role: RoleMetadata) -> PolicyBundle:
        inline = self._get_role_inline_policies(role.role_name)
        managed = self._get_role_managed_policies(role.role_name)

        return PolicyBundle(
            principal_id=role.role_id,
            principal_type="Role",
            resource=Resource(
                type="AwsIamRole",
                id=role.arn,
                name=role.role_name,
                tags=role.tags,
            ),
            inline_policies=inline,
            managed_policies=managed,
        )

    async def fetch_user_bundle(self, user: UserMetadata) -> PolicyBundle:
        return await asyncio.to_thread(self._fetch_user_bundle_sync, user)

    def _fetch_user_bundle_sync(self, user: UserMetadata) -> PolicyBundle:
        inline = self._get_user_inline_policies(user.user_name)
        managed = self._get_user_managed_policies(user.user_name)

        return PolicyBundle(
            principal_id=user.user_id,
            principal_type="User",
            resource=Resource(
                type="AwsIamUser",
                id=user.arn,
                name=user.user_name,
                tags=user.tags,
            ),
            inline_policies=inline,
            managed_policies=managed,
        )

    # ── CloudTrail ────────────────────────────────────────────────────

    async def get_cloudtrail_summary(
        self, principal_arn: str
    ) -> CloudTrailSummary:
        return await asyncio.to_thread(
            self._get_cloudtrail_summary_sync, principal_arn
        )

    def _get_cloudtrail_summary_sync(
        self, principal_arn: str
    ) -> CloudTrailSummary:
        summary = CloudTrailSummary(principal_arn=principal_arn)
        try:
            paginator = self._cloudtrail.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[
                    {"AttributeKey": "Username", "AttributeValue": principal_arn}
                ],
                MaxResults=50,
            ):
                for event in page.get("Events", []):
                    svc, _, action = event.get("EventName", "").partition(":")
                    if not action:
                        action = svc
                        svc = event.get("EventSource", "unknown").split(".")[0]
                    summary.call_counts.setdefault(svc, {})
                    summary.call_counts[svc][action] = (
                        summary.call_counts[svc].get(action, 0) + 1
                    )
                    summary.total_calls_30d += 1
        except ClientError as exc:
            logger.warning(
                "CloudTrail lookup failed for %s: %s",
                principal_arn,
                exc.response["Error"]["Code"],
            )
        return summary

    # ── Internal helpers ──────────────────────────────────────────────

    def _get_role_tags(self, role_name: str) -> dict[str, str]:
        """Paginated role tag fetch — single-page call misses tags beyond 100."""
        try:
            tags = {}
            paginator = self._iam.get_paginator("list_role_tags")
            for page in paginator.paginate(RoleName=role_name):
                for t in page.get("Tags", []):
                    tags[t["Key"]] = t["Value"]
            return tags
        except ClientError:
            return {}

    def _get_role_inline_policies(self, role_name: str) -> list[dict]:
        policies = []
        try:
            paginator = self._iam.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy_name in page.get("PolicyNames", []):
                    resp = self._iam.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )
                    policies.append({
                        "PolicyName": policy_name,
                        "Document": resp["PolicyDocument"],
                        "Type": "Inline",
                    })
        except ClientError as exc:
            logger.warning("Could not fetch inline policies for %s: %s", role_name, exc)
        return policies

    def _get_role_managed_policies(self, role_name: str) -> list[dict]:
        policies = []
        try:
            paginator = self._iam.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get("AttachedPolicies", []):
                    doc = self._fetch_policy_document(policy["PolicyArn"])
                    policies.append({
                        "PolicyName": policy["PolicyName"],
                        "PolicyArn": policy["PolicyArn"],
                        "Document": doc,
                        "Type": "Managed",
                    })
        except ClientError as exc:
            logger.warning("Could not fetch managed policies for %s: %s", role_name, exc)
        return policies

    def _get_user_inline_policies(self, user_name: str) -> list[dict]:
        policies = []
        try:
            paginator = self._iam.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy_name in page.get("PolicyNames", []):
                    resp = self._iam.get_user_policy(
                        UserName=user_name, PolicyName=policy_name
                    )
                    policies.append({
                        "PolicyName": policy_name,
                        "Document": resp["PolicyDocument"],
                        "Type": "Inline",
                    })
        except ClientError as exc:
            logger.warning("Could not fetch inline policies for user %s: %s", user_name, exc)
        return policies

    def _get_user_managed_policies(self, user_name: str) -> list[dict]:
        policies = []
        try:
            paginator = self._iam.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy in page.get("AttachedPolicies", []):
                    doc = self._fetch_policy_document(policy["PolicyArn"])
                    policies.append({
                        "PolicyName": policy["PolicyName"],
                        "PolicyArn": policy["PolicyArn"],
                        "Document": doc,
                        "Type": "Managed",
                    })
        except ClientError as exc:
            logger.warning("Could not fetch managed policies for user %s: %s", user_name, exc)
        return policies

    def _fetch_policy_document(self, policy_arn: str) -> dict:
        try:
            version_id = self._iam.get_policy(PolicyArn=policy_arn)["Policy"][
                "DefaultVersionId"
            ]
            doc = self._iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )["PolicyVersion"]["Document"]
            return doc
        except ClientError as exc:
            logger.warning("Could not fetch document for %s: %s", policy_arn, exc)
            return {}