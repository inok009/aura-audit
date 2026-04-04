from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingType(str, Enum):
    FUNCTIONAL_OVERPRIVILEGE = "FUNCTIONAL_OVERPRIVILEGE"
    WILDCARD_ACTION = "WILDCARD_ACTION"
    WILDCARD_RESOURCE = "WILDCARD_RESOURCE"
    PUBLIC_RESOURCE = "PUBLIC_RESOURCE"
    SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"
    DANGEROUS_ACTION = "DANGEROUS_ACTION"
    ADMIN_POLICY = "ADMIN_POLICY"


class Resource(BaseModel):
    type: str                        # e.g. "AwsIamRole"
    id: str                          # ARN
    name: str
    tags: dict[str, str] = Field(default_factory=dict)


class Remediation(BaseModel):
    recommendation: str
    reference_url: str = ""


class PolicyBundle(BaseModel):
    principal_id: str
    principal_type: str              # "Role" | "User" | "Group"
    resource: Resource
    inline_policies: list[dict[str, Any]] = Field(default_factory=list)
    managed_policies: list[dict[str, Any]] = Field(default_factory=list)
    permission_boundaries: list[dict[str, Any]] = Field(default_factory=list)
    scps: list[dict[str, Any]] = Field(default_factory=list)
    cloudtrail_summary: dict[str, Any] = Field(default_factory=dict)
    semantic_intent: str = ""        # populated by ContextEngine


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "2025-01-01"
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tool: dict[str, str] = Field(
        default_factory=lambda: {
            "name": "Aura-Audit",
            "version": "0.1.0",
            "vendor": "local",
        }
    )
    severity: Severity
    finding_type: FindingType
    title: str
    description: str
    resource: Resource
    offending_statement: dict[str, Any] | None = None
    semantic_context: str = ""
    ai_reasoning: str = ""
    remediation: Remediation
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    tier: int = Field(description="1=Heuristic, 2=Semantic, 3=AI-Inferred")