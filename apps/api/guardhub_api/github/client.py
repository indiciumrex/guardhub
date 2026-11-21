"""GitHub REST client for the GuardHub GitHub App (ADR-0006).

Does: App JWTs (RS256, 9-minute lifetime) from the private key file; installation tokens narrowed
to ONE repository with contents:read; the install-time code exchange and the
"is this installation really yours" check; user-token revocation; uninstalling.
Does not: store any token, write to any repository, follow redirects, or read repository content
(the scanner does that with the narrowed token).
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import httpx
import jwt

from guardhub_api.config import Settings, get_settings

TIMEOUT = httpx.Timeout(15.0, connect=5.0)
USER_AGENT = "GuardHub/1.0 (+https://guardhub.dev)"
MAX_PAGES = 10  # 1,000 repositories / installations


class GitHubAccessError(Exception):
    """The App cannot (or can no longer) act on this installation or repository."""


class GitHubUnavailableError(Exception):
    """GitHub did not answer usefully right now (network, 5xx, rate limit)."""


@dataclass(frozen=True, slots=True)
class Installation:
    installation_id: int
    account_login: str
    account_type: str


@dataclass(frozen=True, slots=True)
class Repository:
    repo_id: int
    full_name: str
    private: bool


@lru_cache(maxsize=2)
def _private_key(path: str) -> str:
    return Path(path).read_text(encoding="ascii")


class GitHubClient:
    def __init__(self, settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings or get_settings()
        self._transport = transport

    def _client(self, base: str) -> httpx.AsyncClient:
        proxy = self.settings.github_egress_proxy or None
        return httpx.AsyncClient(
            base_url=base,
            timeout=TIMEOUT,
            transport=self._transport,
            proxy=proxy if self._transport is None else None,
            trust_env=False,  # never pick up proxy variables from the environment
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "X-GitHub-Api-Version": "2022-11-28"},
        )

    def app_jwt(self) -> str:
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": self.settings.github_client_id}
        return jwt.encode(payload, _private_key(self.settings.github_private_key_file), algorithm="RS256")

    async def _request(
        self,
        method: str,
        path: str,
        *,
        bearer: str | None = None,
        json: object | None = None,
        params: dict[str, str] | None = None,
        auth: tuple[str, str] | None = None,
        base: str | None = None,
        accept: str = "application/vnd.github+json",
    ) -> httpx.Response:
        headers = {"Accept": accept}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        try:
            async with self._client(base or self.settings.github_api_url) as client:
                resp = await client.request(
                    method, path, headers=headers, json=json, params=params, auth=auth
                )
        except httpx.HTTPError as exc:
            raise GitHubUnavailableError(f"{method} {path}: {type(exc).__name__}") from exc
        if resp.status_code in (401, 403, 404, 422) and not _rate_limited(resp):
            raise GitHubAccessError(f"{method} {path}: HTTP {resp.status_code}")
        if resp.status_code >= 300:
            raise GitHubUnavailableError(f"{method} {path}: HTTP {resp.status_code}")
        return resp

    # ---------------------------------------------------------------- App (JWT) calls

    async def installation(self, installation_id: int) -> Installation:
        resp = await self._request("GET", f"/app/installations/{installation_id}", bearer=self.app_jwt())
        account = resp.json().get("account") or {}
        return Installation(installation_id, str(account.get("login", "")), str(account.get("type", "")))

    async def installation_token(self, installation_id: int, repo_id: int | None) -> str:
        """A one-hour token: contents:read on exactly repo_id (or metadata only to list repos)."""
        body: dict[str, object] = (
            {"repository_ids": [repo_id], "permissions": {"contents": "read", "metadata": "read"}}
            if repo_id is not None
            else {"permissions": {"metadata": "read"}}
        )
        resp = await self._request(
            "POST", f"/app/installations/{installation_id}/access_tokens", bearer=self.app_jwt(), json=body
        )
        token = resp.json().get("token")
        if not isinstance(token, str) or not token:
            raise GitHubUnavailableError("access_tokens: no token in the answer")
        return token

    async def revoke_installation_token(self, token: str) -> None:
        # it expires within the hour anyway
        with contextlib.suppress(GitHubAccessError, GitHubUnavailableError):
            await self._request("DELETE", "/installation/token", bearer=token)

    async def uninstall(self, installation_id: int) -> None:
        """Uninstall the App (kills every token it minted). Already gone counts as done."""
        try:
            await self._request("DELETE", f"/app/installations/{installation_id}", bearer=self.app_jwt())
        except GitHubAccessError:
            return

    async def repositories(self, installation_id: int) -> list[Repository]:
        """Repositories the user selected for this installation (metadata-only token, revoked after)."""
        token = await self.installation_token(installation_id, None)
        try:
            repos: list[Repository] = []
            for page in range(1, MAX_PAGES + 1):
                resp = await self._request(
                    "GET",
                    "/installation/repositories",
                    bearer=token,
                    params={"per_page": "100", "page": str(page)},
                )
                items = resp.json().get("repositories") or []
                for r in items:
                    if isinstance(r.get("id"), int) and isinstance(r.get("full_name"), str):
                        repos.append(Repository(r["id"], r["full_name"], bool(r.get("private"))))
                if len(items) < 100:
                    break
            return repos
        finally:
            await self.revoke_installation_token(token)

    # ---------------------------------------------------------------- install-time user proof

    async def exchange_code(self, code: str) -> str:
        """The one-time `code` from the install callback → a user-to-server token."""
        resp = await self._request(
            "POST",
            "/login/oauth/access_token",
            base=self.settings.github_web_url,
            accept="application/json",  # github.com answers form-encoded otherwise
            json={
                "client_id": self.settings.github_client_id,
                "client_secret": self.settings.github_client_secret.get_secret_value(),
                "code": code,
            },
        )
        token = resp.json().get("access_token")
        if not isinstance(token, str) or not token:
            raise GitHubAccessError("code exchange refused")  # expired, reused or forged code
        return token

    async def user_installation_ids(self, user_token: str) -> set[int]:
        ids: set[int] = set()
        for page in range(1, MAX_PAGES + 1):
            resp = await self._request(
                "GET", "/user/installations", bearer=user_token, params={"per_page": "100", "page": str(page)}
            )
            items = resp.json().get("installations") or []
            ids.update(i["id"] for i in items if isinstance(i.get("id"), int))
            if len(items) < 100:
                break
        return ids

    async def revoke_user_token(self, user_token: str) -> None:
        # user-to-server tokens expire after 8 hours anyway
        with contextlib.suppress(GitHubAccessError, GitHubUnavailableError):
            await self._request(
                "DELETE",
                f"/applications/{self.settings.github_client_id}/token",
                json={"access_token": user_token},
                auth=(self.settings.github_client_id, self.settings.github_client_secret.get_secret_value()),
            )


def make_client() -> GitHubClient:
    """The one place callers get a client (tests replace it with one on a fake transport)."""
    return GitHubClient()


def _rate_limited(resp: httpx.Response) -> bool:
    return resp.status_code in (403, 429) and resp.headers.get("x-ratelimit-remaining") == "0"
