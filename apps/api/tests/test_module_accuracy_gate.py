"""Phase 2 gate: a check module can only be switched on with a measured accuracy that meets the
gate (packages/shared/accuracy.json, written by the validation lab). Fails closed."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from guardhub_api.common.errors import UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.modules import accuracy, registry

MEASURED = {"meets_gate": True, "precision": 1.0, "recall": 1.0, "recall_all": 1.0, "tp": 5, "fp": 0, "fn": 0,
            "fn_outside": 0, "targets": 9}  # fmt: skip


@pytest.fixture
def shared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(get_settings(), "shared_dir", tmp_path)
    accuracy._load.cache_clear()
    yield tmp_path
    accuracy._load.cache_clear()


def write(dir_: Path, checks: dict[str, dict[str, object]]) -> None:
    (dir_ / "accuracy.json").write_text(
        json.dumps({"version": 1, "gate": {}, "checks": checks}), encoding="utf-8"
    )
    accuracy._load.cache_clear()


def test_only_measured_checks_that_meet_the_gate_may_be_enabled(shared: Path) -> None:
    write(shared, {"info_leak": MEASURED, "open_admin": {**MEASURED, "meets_gate": False, "precision": 0.5}})
    assert accuracy.may_enable("info_leak") is True
    assert accuracy.may_enable("open_admin") is False  # measured, below the gate
    assert accuracy.may_enable("tls_cert") is False  # never measured
    m = accuracy.measured("info_leak")
    assert m is not None and m.tp == 5 and m.precision == 1.0


@pytest.mark.parametrize(
    "content", [None, "not json", '{"version": 1}', '{"checks": {"info_leak": {"meets_gate": "yes"}}}']
)
def test_fails_closed_without_a_valid_file(shared: Path, content: str | None) -> None:
    if content is not None:
        (shared / "accuracy.json").write_text(content, encoding="utf-8")
    assert accuracy.may_enable("info_leak") is False


class _FakeSession:
    def __init__(self, module: SimpleNamespace) -> None:
        self.module = module

    async def execute(self, _stmt: object) -> SimpleNamespace:
        return SimpleNamespace(scalar_one_or_none=lambda: self.module)

    async def flush(self) -> None:
        return None


async def test_set_enabled_refuses_unmeasured_checks_but_always_allows_off(
    shared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(shared, {"info_leak": MEASURED})
    recorded: list[str] = []

    async def record(_s: object, **kw: object) -> None:
        recorded.append(str(kw["target"]))

    monkeypatch.setattr(registry.audit, "record", record)

    def module(key: str, on: bool) -> SimpleNamespace:
        return SimpleNamespace(
            key=key, name=key, category="c", enabled_global=on, min_plan="free", maintenance=False
        )

    with pytest.raises(UnprocessableError) as exc:
        await registry.set_enabled(  # type: ignore[arg-type]
            _FakeSession(module("tls_cert", False)), key="tls_cert", enabled=True, actor="a"
        )
    assert exc.value.code == "module_not_measured" and recorded == []

    view = await registry.set_enabled(  # type: ignore[arg-type]
        _FakeSession(module("info_leak", False)), key="info_leak", enabled=True, actor="a"
    )
    assert view.enabled_global is True and view.accuracy is not None and view.accuracy.tp == 5

    # switching OFF is never blocked, measured or not
    view = await registry.set_enabled(  # type: ignore[arg-type]
        _FakeSession(module("tls_cert", True)), key="tls_cert", enabled=False, actor="a"
    )
    assert view.enabled_global is False and view.accuracy is None
    # a feature module that is not a check is not gated
    view = await registry.set_enabled(  # type: ignore[arg-type]
        _FakeSession(module("trust_page", False)), key="trust_page", enabled=True, actor="a"
    )
    assert view.enabled_global is True
    assert recorded == ["info_leak", "tls_cert", "trust_page"]
