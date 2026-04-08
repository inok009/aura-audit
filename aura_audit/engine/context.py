"""
Context Engine — Tier-2 Semantic Intent Extraction.

Parses role/user names and resource tags to derive a human-readable
'Semantic Intent' string used to prime the Inference Bridge.

Matching strategy:
  - Primary:   role/user name tokens only
  - Secondary: trusted tag keys only (name, role, function)
  - Excluded:  free-text tag values (description, purpose, team, environment)
               to prevent incidental words like 'pipeline' in a description
               from corrupting the primary intent classification.
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
    # Admin — sre intentionally excluded, handled by dedicated pattern below
    r"admin|administrator|superuser|root|platform[_\-]?eng": (
        "broad administrative access — verify intentional"
    ),
    # SRE — operational, not admin
    r"sre|site[_\-]?reliability": (
        "operational access: infrastructure monitoring, incident response, "
        "no IAM or org-level permissions expected"
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

# Tag keys whose values are safe to match patterns against.
# Free-text keys like 'description', 'purpose', 'team', 'environment'
# are excluded because they frequently contain incidental words
# (e.g. "siem log ingestion pipeline") that corrupt intent classification.
_TRUSTED_TAG_KEYS: frozenset[str] = frozenset({"name", "role", "function"})


@dataclass
class SemanticIntent:
    raw_name: str
    tags: dict[str, str]
    intent_description: str
    keywords_matched: list[str] = field(default_factory=list)
    confidence: float = 0.5


class ContextEngine:
    """
    Derives intent from names and a curated subset of tag keys.
    Returns a SemanticIntent that the SemanticAuditor injects into
    each AI AuditRequest.
    """

    def extract(self, name: str, tags: dict[str, str]) -> SemanticIntent:
        # Primary match: role/user name only
        name_matches: list[tuple[str, str]] = []
        for pattern, description in _INTENT_MAP.items():
            m = re.search(pattern, name, re.IGNORECASE)
            if m:
                name_matches.append((m.group(0), description))

        # Secondary match: trusted tag keys only, not free-text values
        trusted_tag_corpus = " ".join(
            v for k, v in tags.items()
            if k.lower() in _TRUSTED_TAG_KEYS
        )
        tag_matches: list[tuple[str, str]] = []
        if trusted_tag_corpus:
            seen_descriptions = {d for _, d in name_matches}
            for pattern, description in _INTENT_MAP.items():
                if description in seen_descriptions:
                    continue
                m = re.search(pattern, trusted_tag_corpus, re.IGNORECASE)
                if m:
                    tag_matches.append((m.group(0), description))

        all_matches = name_matches + tag_matches

        if not all_matches:
            return SemanticIntent(
                raw_name=name,
                tags=tags,
                intent_description=(
                    f"No clear semantic pattern detected in '{name}'. "
                    f"Audit all permissions conservatively. "
                    f"Pay attention to any destructive, IAM, or cross-account actions."
                ),
                confidence=0.2,
            )

        keywords = [m[0] for m in all_matches]
        descriptions = "; ".join(dict.fromkeys(m[1] for m in all_matches))

        # Name matches carry higher base confidence than tag-only matches
        base = 0.6 if name_matches else 0.4
        confidence = min(base + 0.1 * len(all_matches), 0.95)

        return SemanticIntent(
            raw_name=name,
            tags=tags,
            intent_description=descriptions,
            keywords_matched=keywords,
            confidence=confidence,
        )