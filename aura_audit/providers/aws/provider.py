"""
AWSProvider — concrete implementation of CloudProvider for AWS.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from ..base import CloudProvider
from ...schemas.finding import PolicyBundle
from .ingestion import AWSIngestion

logger = logging.getLogger("aura_audit.aws_provider")


class AWSProvider(CloudProvider):
    def __init__(self, profile: str | None = None, region: str = "us-east-1") -> None:
        try:
            self._session = boto3.Session(
                profile_name=profile,
                region_name=region,
            )
            self._region = region
            self._ingestion = AWSIngestion(self._session, region)
        except ProfileNotFound as exc:
            raise RuntimeError(f"AWS profile not found: {exc}") from exc

    async def get_caller_identity(self) -> dict[str, str]:
        sts = self._session.client("sts")
        return await asyncio.to_thread(sts.get_caller_identity)

    async def list_principals(
        self,
        principal_type: str = "all",
        specific_arn: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Returns a flat list of principal descriptors.
        Each item carries: type, arn, name, id.
        """
        principals = []
        pt = principal_type.lower()

        if specific_arn:
            return [self._arn_to_descriptor(specific_arn)]

        if pt in ("role", "all"):
            roles = await self._ingestion.list_roles()
            principals += [
                {"type": "role", "arn": r.arn, "name": r.role_name,
                 "id": r.role_id, "_meta": r}
                for r in roles
            ]

        if pt in ("user", "all"):
            users = await self._ingestion.list_users()
            principals += [
                {"type": "user", "arn": u.arn, "name": u.user_name,
                 "id": u.user_id, "_meta": u}
                for u in users
            ]

        if pt in ("group", "all"):
            groups = await self._ingestion.list_groups()
            principals += [
                {"type": "group", "arn": g.arn, "name": g.group_name,
                 "id": g.group_id, "_meta": g}
                for g in groups
            ]

        return principals

    async def fetch_policy_bundle(
        self, principal: dict[str, Any]
    ) -> PolicyBundle:
        ptype = principal["type"]
        meta = principal["_meta"]

        if ptype == "role":
            bundle = await self._ingestion.fetch_role_bundle(meta)
        elif ptype == "user":
            bundle = await self._ingestion.fetch_user_bundle(meta)
        else:
            # Groups: return an empty bundle for now (future work)
            from ...schemas.finding import Resource
            bundle = PolicyBundle(
                principal_id=principal["id"],
                principal_type="Group",
                resource=Resource(
                    type="AwsIamGroup",
                    id=principal["arn"],
                    name=principal["name"],
                ),
            )

        # Enrich with CloudTrail
        ct = await self._ingestion.get_cloudtrail_summary(principal["arn"])
        bundle.cloudtrail_summary = {
            svc: calls for svc, calls in ct.call_counts.items()
        }
        return bundle

    async def fetch_policy_bundles(self, principal_ids):
        for pid in principal_ids:
            yield await self.fetch_policy_bundle(pid)

    async def get_cloudtrail_summary(self, principal_id: str) -> dict:
        ct = await self._ingestion.get_cloudtrail_summary(principal_id)
        return ct.call_counts

    def _arn_to_descriptor(self, arn: str) -> dict[str, Any]:
        """Convert a bare ARN string into a principal descriptor dict."""
        parts = arn.split(":")
        resource = parts[-1] if parts else arn
        if "/role/" in arn:
            ptype, name = "role", resource.split("/")[-1]
        elif "/user/" in arn:
            ptype, name = "user", resource.split("/")[-1]
        elif "/group/" in arn:
            ptype, name = "group", resource.split("/")[-1]
        else:
            ptype, name = "role", arn

        return {
            "type": ptype,
            "arn": arn,
            "name": name,
            "id": arn,         # will be resolved during ingestion
            "_meta": None,     # provider will handle None meta gracefully
        }