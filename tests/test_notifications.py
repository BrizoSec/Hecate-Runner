"""Tests for the Slack draft-created notification hook."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from sec7669.config import Settings
from sec7669.notifications import notify_draft_created
from sec7669.orchestrator import RunResult


def test_noop_when_webhook_not_configured(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: calls.append((a, kw)))

    result = RunResult(outcome="draft_created", hunt_id="H-0001", draft_path=Path("/tmp/H-0001.md"))
    notify_draft_created(settings, result)

    assert calls == []


def test_posts_to_webhook_when_configured(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings.model_copy(update={"slack_webhook_url": "https://hooks.slack.com/services/test"})
    captured = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)

    result = RunResult(
        outcome="draft_created",
        hunt_id="H-0042",
        draft_path=Path("/workspace/hunts/production/2026/Q3/H-0042.md"),
        research_id="R-0007",
    )
    notify_draft_created(settings, result)

    assert captured["url"] == "https://hooks.slack.com/services/test"
    assert "H-0042" in captured["json"]["text"]
    assert "R-0007" in captured["json"]["text"]
    assert "grounded by R-0007" in captured["json"]["text"]


def test_ungrounded_draft_says_so(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = settings.model_copy(update={"slack_webhook_url": "https://hooks.slack.com/services/test"})
    captured = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        captured["json"] = json
        return FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)

    result = RunResult(outcome="draft_created", hunt_id="H-0042", draft_path=Path("/tmp/H-0042.md"))
    notify_draft_created(settings, result)

    assert "ungrounded" in captured["json"]["text"]


def test_http_failure_is_swallowed_not_raised(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings.model_copy(update={"slack_webhook_url": "https://hooks.slack.com/services/test"})

    def fake_post(url: str, json: dict, timeout: float):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", fake_post)

    result = RunResult(outcome="draft_created", hunt_id="H-0042", draft_path=Path("/tmp/H-0042.md"))
    # Must not raise.
    notify_draft_created(settings, result)


def test_non_2xx_response_is_swallowed_not_raised(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings.model_copy(update={"slack_webhook_url": "https://hooks.slack.com/services/test"})

    class FailingResponse:
        def raise_for_status(self) -> None:
            raise httpx.HTTPStatusError("bad webhook", request=None, response=None)  # type: ignore[arg-type]

    def fake_post(url: str, json: dict, timeout: float) -> FailingResponse:
        return FailingResponse()

    monkeypatch.setattr(httpx, "post", fake_post)

    result = RunResult(outcome="draft_created", hunt_id="H-0042", draft_path=Path("/tmp/H-0042.md"))
    # Must not raise.
    notify_draft_created(settings, result)
