"""
Re-export AuditRequest from inference.bridge for convenience.
Kept here so schemas/ is the single source of truth for consumers.
"""
from ..inference.bridge import AuditRequest, InferenceResult

__all__ = ["AuditRequest", "InferenceResult"]