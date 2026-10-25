"""Tests for the Slack draft-created notification hook."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from hecate_runner.config import Settings
from hecate_runner.notifications import notify_draft_created
from hecate_runner.orchestrator import RunResult


def test_noop_when_webhook_not_configured(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings.model_copy(update={"slack_webhook_url": None, "slack_bot_token": None})
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: calls.append((a, kw)))

    result = RunResult(outcome="draft_created", hunt_id="H-0001", draft_path=Path("/tmp/H-0001.md"))
    notify_draft_created(settings, result)

    assert calls == []


def test_posts_to_webhook_when_configured(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings.model_copy(
        update={"slack_webhook_url": "https://hooks.slack.com/services/test"}
    )
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
        draft_path=Path("/workspace/hunts/2026/Q3/H-0042.md"),
        research_id="R-0007",
    )
    notify_draft_created(settings, result)

    assert captured["url"] == "https://hooks.slack.com/services/test"
    assert "H-0042" in captured["json"]["text"]
    assert "R-0007" in captured["json"]["text"]
    assert "research context R-0007" in captured["json"]["text"]


def test_notification_says_when_research_context_was_not_created(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings.model_copy(
        update={"slack_webhook_url": "https://hooks.slack.com/services/test"}
    )
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

    assert "no research context" in captured["json"]["text"]


def test_http_failure_is_swallowed_not_raised(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings.model_copy(
        update={"slack_webhook_url": "https://hooks.slack.com/services/test"}
    )

    def fake_post(url: str, json: dict, timeout: float):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", fake_post)

    result = RunResult(outcome="draft_created", hunt_id="H-0042", draft_path=Path("/tmp/H-0042.md"))
    # Must not raise.
    notify_draft_created(settings, result)


def test_invalid_url_is_swallowed_not_raised(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test: a malformed HECATE_RUNNER_SLACK_WEBHOOK_URL makes httpx.post
    itself raise httpx.InvalidURL, which inherits directly from Exception --
    NOT from httpx.HTTPError. The old `except httpx.HTTPError` didn't catch
    it, violating this module's own stated contract ("every function here
    catches its own errors ... instead of raising")."""
    settings = settings.model_copy(update={"slack_webhook_url": "not-a-valid-url"})

    def fake_post(url: str, json: dict, timeout: float):
        raise httpx.InvalidURL("malformed webhook URL")

    monkeypatch.setattr(httpx, "post", fake_post)

    result = RunResult(outcome="draft_created", hunt_id="H-0042", draft_path=Path("/tmp/H-0042.md"))
    # Must not raise.
    notify_draft_created(settings, result)


def test_non_2xx_response_is_swallowed_not_raised(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings.model_copy(
        update={"slack_webhook_url": "https://hooks.slack.com/services/test"}
    )

    class FailingResponse:
        def raise_for_status(self) -> None:
            raise httpx.HTTPStatusError("bad webhook", request=None, response=None)  # type: ignore[arg-type]

    def fake_post(url: str, json: dict, timeout: float) -> FailingResponse:
        return FailingResponse()

    monkeypatch.setattr(httpx, "post", fake_post)

    result = RunResult(outcome="draft_created", hunt_id="H-0042", draft_path=Path("/tmp/H-0042.md"))
    # Must not raise.
    notify_draft_created(settings, result)


def test_send_test_notification_unconfigured(settings: Settings) -> None:
    from hecate_runner.notifications import send_test_notification

    settings = settings.model_copy(update={"slack_webhook_url": None, "slack_bot_token": None})
    success, msg = send_test_notification(settings)
    assert not success
    assert "not configured" in msg


def test_send_test_notification_success(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hecate_runner.notifications import send_test_notification

    settings = settings.model_copy(
        update={"slack_webhook_url": "https://hooks.slack.com/services/test"}
    )

    class OkResponse:
        def raise_for_status(self) -> None:
            pass

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: OkResponse())
    success, msg = send_test_notification(settings)
    assert success
    assert "successfully" in msg


def test_send_test_notification_failure(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hecate_runner.notifications import send_test_notification

    settings = settings.model_copy(
        update={"slack_webhook_url": "https://hooks.slack.com/services/test"}
    )

    def fake_post(*a, **kw):
        raise httpx.ConnectError("network unreachable")

    monkeypatch.setattr(httpx, "post", fake_post)
    success, msg = send_test_notification(settings)
    assert not success
    assert "failed" in msg


def test_bot_token_post_message_success(settings: Settings) -> None:
    from hecate_runner.notifications import SlackNotificationRouter

    settings = settings.model_copy(
        update={
            "slack_bot_token": "xoxb-test-bot-token",
            "slack_webhook_url": None,
        }
    )

    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization")
        captured["body"] = request.read().decode("utf-8")
        return httpx.Response(200, json={"ok": True, "ts": "1234567890.123456"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    router = SlackNotificationRouter(settings, client=client)

    success, msg = router.post_message("#threat-exploits-epss", "Alert: EPSS Spike")
    assert success
    assert "successfully" in msg
    assert captured["url"] == "https://slack.com/api/chat.postMessage"
    assert captured["auth"] == "Bearer xoxb-test-bot-token"
    assert "#threat-exploits-epss" in captured["body"]


def test_bot_token_api_error_swallowed(settings: Settings) -> None:
    from hecate_runner.notifications import SlackNotificationRouter

    settings = settings.model_copy(
        update={
            "slack_bot_token": "xoxb-test-bot-token",
            "slack_webhook_url": None,
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "channel_not_found"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    router = SlackNotificationRouter(settings, client=client)

    success, msg = router.post_message("#nonexistent", "Hello")
    assert not success
    assert "channel_not_found" in msg


def test_resolve_threat_channel_profiles(settings: Settings) -> None:
    from hecate_runner.notifications import SlackNotificationRouter

    router = SlackNotificationRouter(settings)

    # Vulnerability / EPSS
    assert router.resolve_threat_channel("vulnerability_advisory") == settings.slack_channel_exploits
    assert router.resolve_threat_channel("", "first_org") == settings.slack_channel_exploits

    # Sandbox
    assert router.resolve_threat_channel("sandbox_execution") == settings.slack_channel_sandbox
    assert router.resolve_threat_channel("", "anyrun") == settings.slack_channel_sandbox

    # APT / STIX 2.1
    assert router.resolve_threat_channel("procedural_intrusion") == settings.slack_channel_apt
    assert router.resolve_threat_channel("", "opencti") == settings.slack_channel_apt

    # Cloud & Identity
    assert router.resolve_threat_channel("cloud_audit_telemetry") == settings.slack_channel_cloud
    assert router.resolve_threat_channel("", "cloud_threat") == settings.slack_channel_cloud

    # C2
    assert router.resolve_threat_channel("network_telemetry") == settings.slack_channel_c2
    assert router.resolve_threat_channel("", "censys_c2") == settings.slack_channel_c2


def test_notify_hunt_completed_and_purple_team(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from hecate_runner.notifications import notify_hunt_completed, notify_purple_team

    settings = settings.model_copy(
        update={
            "slack_bot_token": "xoxb-test-bot",
        }
    )

    captured_posts = []

    def fake_post(self, channel: str, text: str, **kw):
        captured_posts.append((channel, text))
        return True, "ok"

    from hecate_runner.notifications import SlackNotificationRouter

    monkeypatch.setattr(SlackNotificationRouter, "post_message", fake_post)

    notify_hunt_completed(
        settings,
        hunt_id="H-0851",
        topic="DarkGate C2 Hunting",
        techniques=["T1071.001", "T1059.001"],
        sigma_count=15,
        pr_url="https://github.com/BrizoSec/Hecate-Content/pull/30",
        misp_event_id="139",
    )

    notify_purple_team(
        settings,
        hunt_id="H-0851",
        technique="T1071.001",
        success=True,
        telemetry_count=42,
        summary="Emulation beacon captured in Zeek HTTP logs",
    )

    assert len(captured_posts) == 2
    assert captured_posts[0][0] == settings.slack_channel_hunts_exec
    assert "DarkGate C2 Hunting" in captured_posts[0][1]
    assert "Event #139" in captured_posts[0][1]

    assert captured_posts[1][0] == settings.slack_channel_purple_team
    assert "Detection Validated" in captured_posts[1][1]
    assert "42 events" in captured_posts[1][1]


def test_send_test_all_channels(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from hecate_runner.notifications import send_test_all_channels

    settings = settings.model_copy(
        update={"slack_bot_token": "xoxb-test-bot"}
    )

    def fake_post(self, channel: str, text: str, **kw):
        return True, f"Sent to {channel}"

    from hecate_runner.notifications import SlackNotificationRouter

    monkeypatch.setattr(SlackNotificationRouter, "post_message", fake_post)

    results = send_test_all_channels(settings)
    assert len(results) == 11
    assert settings.slack_channel_ops_metrics in results
    assert settings.slack_channel_detection_engineering in results
    assert settings.slack_channel_threat_intel in results
    assert settings.slack_channel_threat_hunting in results
    assert settings.slack_channel_exploits in results
    assert results[settings.slack_channel_ops_metrics][0] is True


def test_notify_ops_metrics_custom_channel(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from hecate_runner.notifications import SlackNotificationRouter, notify_ops_metrics

    settings = settings.model_copy(update={"slack_bot_token": "xoxb-test-bot"})
    captured = []

    def fake_post(self, channel: str, text: str, **kw):
        captured.append((channel, text, kw.get("attachments")))
        return True, "ok"

    monkeypatch.setattr(SlackNotificationRouter, "post_message", fake_post)

    notify_ops_metrics(
        settings,
        metrics_summary={"hunts_completed": 5, "sigma_rules_produced": 40, "spend_today_usd": 1.25},
        channel="#custom-metrics",
    )

    assert len(captured) == 1
    assert captured[0][0] == "#custom-metrics"
    assert "Hecate Daily Autonomous Ops" in captured[0][1]
    assert captured[0][2] is not None


def test_specialized_daily_digests_dispatch(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from hecate_runner.notifications import (
        SlackNotificationRouter,
        notify_detection_digest,
        notify_threat_hunting_digest,
        notify_threat_intel_digest,
    )

    settings = settings.model_copy(update={"slack_bot_token": "xoxb-test-bot"})
    dispatched = []

    def fake_post(self, channel: str, text: str, **kw):
        dispatched.append((channel, text, kw.get("attachments")))
        return True, "delivered"

    monkeypatch.setattr(SlackNotificationRouter, "post_message", fake_post)

    # 1. Detection Engineering
    ok1, _ = notify_detection_digest(settings, {"total_sigma_rules": 500, "pass_rate_pct": "95%"})
    assert ok1 is True
    assert dispatched[-1][0] == settings.slack_channel_detection_engineering
    assert "Detection Engineering" in dispatched[-1][1]

    # 2. Threat Intel
    ok2, _ = notify_threat_intel_digest(settings, {"total_sources_count": 12, "recent_research_count": 4})
    assert ok2 is True
    assert dispatched[-1][0] == settings.slack_channel_threat_intel
    assert "Threat Intelligence" in dispatched[-1][1]

    # 3. Threat Hunting
    ok3, _ = notify_threat_hunting_digest(settings, {"recent_hunts_count": 2, "total_hunts": 200})
    assert ok3 is True
    assert dispatched[-1][0] == settings.slack_channel_threat_hunting
    assert "Threat Hunting" in dispatched[-1][1]



