"""Operator CLI: promote an existing user to admin (or demote). The action is audited.

There's no HTTP route that grants admin, so the first admin is created by an operator with shell
access:  docker compose exec api python -m guardhub_api.admin.bootstrap promote you@example.com
The user must already be registered with 2FA enabled (§8.3: admin needs role + 2FA).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from guardhub_api.auth import repository
from guardhub_api.common import audit
from guardhub_api.db.session import DbContext, db_session, dispose_engine


async def _set_role(email: str, role: str) -> int:
    try:
        async with db_session(DbContext.system()) as session:
            user = await repository.by_email(session, email)
            if user is None:
                print(f"no user with email {email}", file=sys.stderr)
                return 1
            if role == "admin" and not user.totp_enabled:
                print("user must enable two-factor authentication before becoming admin", file=sys.stderr)
                return 1
            user.role = role
            await audit.record(session, actor="operator:cli", action=f"admin.{role}_set", target=str(user.id))
            print(f"{email} is now '{role}'")
            return 0
    finally:
        await dispose_engine()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["promote", "demote"])
    parser.add_argument("email")
    args = parser.parse_args()
    return asyncio.run(_set_role(args.email.lower(), "admin" if args.action == "promote" else "user"))


if __name__ == "__main__":
    raise SystemExit(main())
