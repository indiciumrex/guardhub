"""The one question the project flows ask about trusted domains (ADR-0003):

"Does this user hold a currently valid trusted-domain proof for exactly this origin?"

True only when ALL hold: the user's role is `admin` in the database (not just in the session
token), they own an `active` trusted domain whose verified origin equals `origin` exactly (same
scheme, host and port; subdomains never match), and that proof was confirmed within
`PROOF_MAX_AGE`. Anything else answers False, so callers fall back to the normal proof flow.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from guardhub_api.admin.trusted_domains import repository
from guardhub_api.auth import service as auth_service
from guardhub_api.common.errors import UnauthenticatedError, UnprocessableError
from guardhub_api.db.session import DbContext, db_session

TRUSTED_DOMAIN_METHOD = "trusted_domain"
# Same window as a project's own proof (projects.service.REVERIFY_AFTER). The daily background
# re-check keeps active domains well inside it; if that job stops, trust lapses on its own.
PROOF_MAX_AGE = timedelta(days=30)


async def trusted_domain_covers(user_id: uuid.UUID, origin: str) -> bool:
    """Whether `user_id` may treat `origin` as verified through an active trusted domain."""
    try:
        role = await auth_service.current_role(user_id)
    except UnauthenticatedError:
        return False
    if role != "admin":
        return False
    proven_since = datetime.now(UTC) - PROOF_MAX_AGE
    async with db_session(DbContext(role="admin", user_id=user_id)) as session:
        return await repository.active_for_origin(session, user_id, origin, proven_since) is not None


async def require_trusted_domain(user_id: uuid.UUID, origin: str) -> None:
    """Raise 422 `trusted_domain_inactive` unless `trusted_domain_covers(user_id, origin)`."""
    if not await trusted_domain_covers(user_id, origin):
        raise UnprocessableError(
            "trusted_domain_inactive",
            "The trusted domain for this site is not active. Verify it again before scanning.",
        )
