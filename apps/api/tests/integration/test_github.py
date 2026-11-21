"""GitHub App connection and repository scans (ADR-0006), end to end against a fake GitHub.

The fake answers like api.github.com / github.com for the calls GuardHub makes and records
them, so the tests can check what GuardHub asked for (narrowed tokens, revocations) as well as
what it did with the answers.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from redis.asyncio import Redis
from sqlalchemy import select, text

from guardhub_api.config import get_settings
from guardhub_api.db.models import AuditLog, GitHubInstallation
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.github import client as github_client
from guardhub_api.scans.queue import JOBS_STREAM, REPO_TOKEN_PREFIX
from tests.integration.conftest import FakeScanner, new_client, signed_in


@dataclass
class FakeGitHub:
    """codes: OAuth code → the installation ids that GitHub user can see."""

    codes: dict[str, set[int]] = field(default_factory=dict)
    accounts: dict[int, tuple[str, str]] = field(default_factory=dict)
    repos: dict[int, list[dict[str, object]]] = field(default_factory=dict)
    uninstalled: set[int] = field(default_factory=set)
    calls: list[tuple[str, str, object]] = field(default_factory=list)
    revoked_user_tokens: list[str] = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, path, body))
        auth = request.headers.get("Authorization", "")
        if request.url.host == "github.com" and path == "/login/oauth/access_token":
            code = (body or {}).get("code")
            if code in self.codes and (body or {}).get("client_secret") == "test-client-secret":
                return httpx.Response(
                    200, json={"access_token": f"user-token-{code}", "token_type": "bearer"}
                )
            return httpx.Response(200, json={"error": "bad_verification_code"})
        if path == "/user/installations":
            code = auth.removeprefix("Bearer user-token-")
            ids = self.codes.get(code, set())
            return httpx.Response(
                200, json={"total_count": len(ids), "installations": [{"id": i} for i in ids]}
            )
        if path.startswith("/applications/") and request.method == "DELETE":
            self.revoked_user_tokens.append((body or {}).get("access_token", ""))
            return httpx.Response(204)
        if path.startswith("/app/installations/"):
            assert auth.startswith("Bearer ey"), "App calls must carry the App JWT"
            parts = path.split("/")
            iid = int(parts[3])
            if iid in self.uninstalled or iid not in self.accounts:
                return httpx.Response(404, json={"message": "Not Found"})
            if request.method == "DELETE":
                self.uninstalled.add(iid)
                return httpx.Response(204)
            if len(parts) == 5 and parts[4] == "access_tokens":
                wanted = (body or {}).get("repository_ids")
                known = {r["id"] for r in self.repos.get(iid, [])}
                if wanted is not None and not set(wanted) <= known:
                    return httpx.Response(422, json={"message": "repository not accessible"})
                return httpx.Response(201, json={"token": f"ghs_install_{iid}_{wanted}", "expires_at": "x"})
            login, kind = self.accounts[iid]
            return httpx.Response(200, json={"id": iid, "account": {"login": login, "type": kind}})
        if path == "/installation/repositories":
            iid = int(auth.split("_")[2])
            return httpx.Response(200, json={"total_count": 1, "repositories": self.repos.get(iid, [])})
        if path == "/installation/token" and request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(599, json={"message": f"unexpected {request.method} {path}"})


@pytest.fixture
async def github(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AsyncIterator[FakeGitHub]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = tmp_path / "app.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    settings = get_settings()
    monkeypatch.setattr(settings, "github_app_slug", "guardhub-test")
    monkeypatch.setattr(settings, "github_client_id", "Iv1.test")
    monkeypatch.setattr(
        settings, "github_client_secret", type(settings.github_client_secret)("test-client-secret")
    )
    monkeypatch.setattr(settings, "github_private_key_file", str(pem))
    fake = FakeGitHub()
    transport = httpx.MockTransport(fake.handler)
    monkeypatch.setattr(github_client, "make_client", lambda: github_client.GitHubClient(transport=transport))
    async with db_session(DbContext.system()) as session:
        await session.execute(
            text("UPDATE modules SET enabled_global = true WHERE key IN ('dependency_vulns', 'repo_secrets')")
        )
    yield fake
    async with db_session(DbContext.system()) as session:
        await session.execute(
            text(
                "UPDATE modules SET enabled_global = false WHERE key IN ('dependency_vulns', 'repo_secrets')"
            )
        )


async def connect(client: httpx.AsyncClient, installation_id: int, code: str) -> httpx.Response:
    r = await client.post("/api/v1/github/connect")
    assert r.status_code == 200, r.text
    state = parse_qs(urlparse(r.json()["install_url"]).query)["state"][0]
    assert r.json()["install_url"].startswith(
        "https://github.com/apps/guardhub-test/installations/new?state="
    )
    return await client.post(
        "/api/v1/github/installations",
        json={"code": code, "installation_id": installation_id, "state": state},
    )


async def test_connect_add_repo_scan_disconnect(
    redis: Redis, scanner: FakeScanner, github: FakeGitHub
) -> None:
    iid = 4200 + uuid.uuid4().int % 1000
    github.accounts[iid] = ("acme", "Organization")
    github.repos[iid] = [
        {"id": 1001, "full_name": "acme/api", "private": True},
        {"id": 1002, "full_name": "acme/web", "private": False},
    ]
    github.codes["a-code"] = {iid}
    async with new_client() as a:
        await signed_in(a)
        r = await a.get("/api/v1/github")
        assert r.json() == {"configured": True, "installations": []}

        r = await connect(a, iid, "a-code")
        assert r.status_code == 201, r.text
        row_id = r.json()["id"]
        assert r.json()["account_login"] == "acme"
        assert github.revoked_user_tokens == ["user-token-a-code"], "the user token is revoked right away"

        # A state is single use.
        r = await a.post("/api/v1/github/connect")
        state = parse_qs(urlparse(r.json()["install_url"]).query)["state"][0]
        body = {"code": "a-code", "installation_id": iid, "state": state}
        assert (await a.post("/api/v1/github/installations", json=body)).status_code == 201
        r = await a.post("/api/v1/github/installations", json=body)
        assert r.status_code == 422 and r.json()["error"]["code"] == "github_state_invalid"

        r = await a.get(f"/api/v1/github/installations/{row_id}/repositories")
        assert r.status_code == 200, r.text
        assert [x["full_name"] for x in r.json()] == ["acme/api", "acme/web"]

        r = await a.post(f"/api/v1/github/installations/{row_id}/repositories", json={"repo_id": 9999})
        assert r.status_code == 404, "a repository the user did not share is never added"
        r = await a.post(f"/api/v1/github/installations/{row_id}/repositories", json={"repo_id": 1001})
        assert r.status_code == 201, r.text
        project = r.json()
        assert project["kind"] == "repo" and project["verified"] and project["repo_full_name"] == "acme/api"
        assert project["target_url"] == "https://github.com/acme/api"
        r = await a.post(f"/api/v1/github/installations/{row_id}/repositories", json={"repo_id": 1001})
        assert r.status_code == 409

        # Scan: a token narrowed to that one repository, contents:read, kept OUT of the job stream.
        github.calls.clear()
        r = await a.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 202, r.text
        mint = [c for c in github.calls if c[1].endswith("/access_tokens")]
        assert mint and mint[-1][2] == {
            "repository_ids": [1001],
            "permissions": {"contents": "read", "metadata": "read"},
        }
        jobs = [json.loads(m[1]["payload"]) for m in await redis.xrange(JOBS_STREAM)]
        job = [j for j in jobs if j.get("kind") == "repo_scan"][-1]
        assert job["repo"] == "acme/api" and set(job["checks"]) == {"dependency_vulns", "repo_secrets"}
        assert job["token_key"] == REPO_TOKEN_PREFIX + job["job_id"]
        assert "ghs_" not in json.dumps(jobs), "no token in the stream"
        assert await redis.get(job["token_key"]) == f"ghs_install_{iid}_[1001]"
        assert 0 < await redis.ttl(job["token_key"]) <= 600

        # Disconnect: uninstalled at GitHub, repo project stops being scannable, history kept.
        r = await a.delete(f"/api/v1/github/installations/{row_id}")
        assert r.status_code == 204
        assert iid in github.uninstalled
        r = await a.get(f"/api/v1/projects/{project['id']}")
        assert r.status_code == 200 and not r.json()["verified"]
        r = await a.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 422
        assert (await a.get("/api/v1/github")).json()["installations"] == []

    async with db_session(DbContext.system()) as session:
        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.target == row_id))).scalars().all()
        )
        assert "github.connect" in actions and "github.disconnect" in actions


async def test_foreign_or_taken_installations_are_refused(
    redis: Redis, scanner: FakeScanner, github: FakeGitHub
) -> None:
    iid = 5200 + uuid.uuid4().int % 1000
    github.accounts[iid] = ("victim", "User")
    github.repos[iid] = [{"id": 2001, "full_name": "victim/secret", "private": True}]
    github.codes["victim-code"] = {iid}
    github.codes["attacker-code"] = {7}  # the attacker's GitHub user only sees its own install
    async with new_client() as victim, new_client("198.51.100.8") as attacker:
        await signed_in(victim)
        await signed_in(attacker)
        # Guessing the victim's installation id is not enough: GitHub must confirm access.
        r = await connect(attacker, iid, "attacker-code")
        assert r.status_code == 422 and r.json()["error"]["code"] == "github_installation_not_yours"
        r = await connect(attacker, iid, "forged-code")
        assert r.status_code == 422
        r = await connect(victim, iid, "victim-code")
        assert r.status_code == 201
        row_id = r.json()["id"]
        # RLS: another user cannot use the victim's installation.
        r = await attacker.get(f"/api/v1/github/installations/{row_id}/repositories")
        assert r.status_code == 404
        r = await attacker.post(f"/api/v1/github/installations/{row_id}/repositories", json={"repo_id": 2001})
        assert r.status_code == 404
        # One owner per installation: a second account is refused even with a real code.
        github.codes["second-code"] = {iid}
        r = await connect(attacker, iid, "second-code")
        assert r.status_code == 409 and r.json()["error"]["code"] == "github_installation_taken"


async def test_uninstalled_on_github_is_detected_at_scan_time(
    redis: Redis, scanner: FakeScanner, github: FakeGitHub
) -> None:
    iid = 6200 + uuid.uuid4().int % 1000
    github.accounts[iid] = ("solo", "User")
    github.repos[iid] = [{"id": 3001, "full_name": "solo/app", "private": True}]
    github.codes["solo-code"] = {iid}
    async with new_client() as c:
        await signed_in(c)
        row_id = (await connect(c, iid, "solo-code")).json()["id"]
        r = await c.post(f"/api/v1/github/installations/{row_id}/repositories", json={"repo_id": 3001})
        project_id = r.json()["id"]
        github.uninstalled.add(iid)  # the user removed the App on github.com
        r = await c.post(f"/api/v1/projects/{project_id}/scans")
        assert r.status_code == 422 and r.json()["error"]["code"] == "repo_access_lost"
    async with db_session(DbContext.system()) as session:
        row = (
            await session.execute(
                select(GitHubInstallation).where(GitHubInstallation.id == uuid.UUID(row_id))
            )
        ).scalar_one()
        assert row.revoked_at is not None


async def test_not_configured(redis: Redis) -> None:
    async with new_client() as c:
        await signed_in(c)
        r = await c.get("/api/v1/github")
        assert r.json()["configured"] is False
        r = await c.post("/api/v1/github/connect")
        assert r.status_code == 503 and r.json()["error"]["code"] == "github_not_configured"
