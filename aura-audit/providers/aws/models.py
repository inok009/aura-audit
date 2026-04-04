"""AWS-specific data transfer objects."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RoleMetadata:
    role_id: str
    role_name: str
    arn: str
    path: str
    tags: dict[str, str]
    description: str = ""
    max_session_duration: int = 3600


@dataclass
class UserMetadata:
    user_id: str
    user_name: str
    arn: str
    path: str
    tags: dict[str, str]


@dataclass
class GroupMetadata:
    group_id: str
    group_name: str
    arn: str
    path: str


@dataclass
class CloudTrailSummary:
    principal_arn: str
    # service → {action → count}
    call_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    last_activity: str | None = None
    total_calls_30d: int = 0