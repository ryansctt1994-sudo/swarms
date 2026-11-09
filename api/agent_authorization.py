"""Pure, testable ownership decision for the experimental Swarms API.

This helper makes no authentication or persistence claim: callers must resolve
the API key to a real user and retrieve owner_id from trusted server-side
metadata before consulting it.
"""
from __future__ import annotations

from uuid import UUID


def may_access_agent(
    owner_id: UUID | None,
    requesting_user_id: UUID,
    *,
    is_admin: bool = False,
) -> bool:
    if not isinstance(owner_id, UUID) or not isinstance(requesting_user_id, UUID):
        return False
    return owner_id == requesting_user_id or is_admin
