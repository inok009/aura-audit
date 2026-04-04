"""
Context Engine — Tier-2 Semantic Intent Extraction.

Parses role/user names and resource tags to derive a human-readable
'Semantic Intent' string used to prime the Inference Bridge.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

# Vocabulary: keyword → inferred capability cluster
_INTENT_MAP: dict[str, str] = {
    # Read-oriented
    r"read[_\-]?only|viewer|observer|monitor|auditor|inspector": (
        "read-only access with no mutative or destructive capabilities"
    ),
    r"billing|finance|cost[_\-]?mgmt": (
        "billing and cost visibility only, no infrastructure control"
    ),
    r"log[_\-]?reader|cloudtrail|siem": (
        "log ingestion and read access, no write or delete operations"
    ),
    # Deployment/CI
    r"deploy[_\-]?|cicd|pipeline|codepipeline|codebuild|jenkins|github[_\-]?actions": (
        "deployment automation: push code and update ECS/Lambda/EKS workloads"
    ),
    r"terraform|infra[_\-]?as[_\-]?code|iac": (
        "infrastructure provisioning via IaC tooling; broad write but controlled"
    ),
    # Data
    r"s3[_\-]?reader|data[_\-]?lake|analytics|athena": (
        "read access to S3/data lake, run Athena queries, no deletions"
    ),
    r"backup|snapshot|dr[_\-]?": (
        "create and restore snapshots/backups, no production workload mutation"
    ),
    # Admin
    r"admin|administrator|superuser|root|sre|platform[_\-]?eng": (
        "broad administrative access — verify intentional"
    ),
    # Lambda/Serverless
    r"lambda[_\-]?exec|function[_\-]?exec|serverless": (
        "Lambda execution: invoke functions, write logs, read config"
    ),
    # Cross-account
    r"cross[_\-]?account|assume[_\-]?role|federation": (
        "cross-account trust role; verify trust policy scope"
    ),
}


@dataclass
class SemanticIntent:
    raw_name: str
    tags: dict[str, str]
    intent_description: str
    keywords_matched: list[str] = field(default_factory=list)
    confidence: float = 0.5


class ContextEngine:
    """
    Derives intent from names, tags, and description fields.
    Returns a SemanticIntent that the SemanticAuditor injects into
    each AI AuditRequest.
    """

    def extract(self, name: str, tags: dict[str, str]) -> SemanticIntent:
        search_corpus = self._build_corpus(name, tags)
        matched_intents: list[tuple[str, str]] = []

        for pattern, description in _INTENT_MAP.items():
            if re.search(pattern, search_corpus, re.IGNORECASE):
                keyword = re.search(pattern, search_corpus, re.IGNORECASE).group(0)
                matched_intents.append((keyword, description))

        if not matched_intents:
            return SemanticIntent(
                raw_name=name,
                tags=tags,
                intent_description=(
                    f"No clear semantic pattern detected in '{name}'. "
                    f"Treat as general-purpose and audit all permissions."
                ),
                confidence=0.2,
            )

        # Merge multiple matches into a composite intent
        keywords = [m[0] for m in matched_intents]
        descriptions = "; ".join(dict.fromkeys(m[1] for m in matched_intents))

        return SemanticIntent(
            raw_name=name,
            tags=tags,
            intent_description=descriptions,
            keywords_matched=keywords,
            confidence=min(0.4 + 0.2 * len(matched_intents), 0.95),
        )

    def _build_corpus(self, name: str, tags: dict[str, str]) -> str:
        tag_values = " ".join(
            f"{k} {v}"
            for k, v in tags.items()
            if k.lower() in {"name", "role", "purpose", "team", "environment", "description"}
        )
        return f"{name} {tag_values}"