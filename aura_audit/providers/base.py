from abc import ABC, abstractmethod
from typing import AsyncIterator
from ..schemas.finding import PolicyBundle


class CloudProvider(ABC):
    """
    Abstract base class for cloud providers.
    Concrete implementations: AWSProvider, AzureProvider (future), GCPProvider (future).
    """

    @abstractmethod
    async def list_principals(self) -> list[dict]:
        """Return all auditable principals (users, roles, groups)."""
        ...

    @abstractmethod
    async def fetch_policy_bundles(
        self, principal_ids: list[str]
    ) -> AsyncIterator[PolicyBundle]:
        """Yield PolicyBundle objects for each principal."""
        ...

    @abstractmethod
    async def get_cloudtrail_summary(self, principal_id: str) -> dict:
        """Return recent API call frequency for a principal."""
        ...