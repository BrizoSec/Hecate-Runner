"""Health is a result of read-only confirmation, never credential presence."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from hecate_agent.core.source_evidence import SourceEvidence

from hecate_runner.config import Settings
from hecate_runner.cti.catalogs import LolbasProvider
from hecate_runner.integration_checks import check_integrations
from hecate_runner.orchestrator import Orchestrator


def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        cti_provider="file",
        hecate_llm_provider="ollama",
        hecate_llm_model="known:latest",
        otx_api_key="configured-key",
    )


def test_read_only_success_failure_disabled_and_no_credentials_in_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TAVILY_API_KEY", "secret-do-not-log")
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "known:latest"}]})
        if request.url.host == "api.tavily.com":
            return httpx.Response(401, json={"error": "secret-do-not-log"})
        return httpx.Response(503)

    results = check_integrations(
        settings(tmp_path), client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    assert results["llm"]["healthy"]
    assert not results["tavily"]["healthy"] and results["tavily"]["enabled"]
    assert results["tavily"]["detail"] == "HTTP 401"
    assert not results["otx"]["enabled"]  # A key alone does not enable a disabled intake source.
    assert all(
        "secret-do-not-log" not in path.read_text()
        for path in (tmp_path / ".hecate/integrations").glob("*.json")
    )
    assert all(
        "submit" not in request.url.path and "send" not in request.url.path for request in seen
    )


def test_html_login_and_invalid_feed_are_not_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    s = settings(tmp_path)
    s.cti_provider = "rss"
    s.rss_feed_urls_raw = "https://test.invalid/feed"
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(
                200, text="<html>Login</html>", headers={"Content-Type": "text/html"}
            )
        )
    )
    result = check_integrations(s, client=client)
    assert not result["rss"]["healthy"]
    assert not result["cisa_narrative"]["healthy"]


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("http_status", [200, 401])
def test_misp_reachability_is_independent_of_source_enablement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool, http_status: int
) -> None:
    monkeypatch.chdir(tmp_path)
    s = settings(tmp_path)
    s.cti_provider = "misp" if enabled else "file"
    s.misp_base_url = "https://misp.test"
    s.misp_api_key = "secret-misp-key"
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "misp.test":
            requests.append(request)
            return httpx.Response(http_status, json={"version": "2.5"})
        return httpx.Response(503)

    result = check_integrations(s, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert len(requests) == 1
    assert requests[0].url.path == "/servers/getVersion"
    assert requests[0].headers["Authorization"] == "secret-misp-key"
    assert result["misp"]["enabled"] is enabled
    assert result["misp"]["healthy"] is (http_status == 200)
    assert not s.misp_cursor_file.exists()
    assert "secret-misp-key" not in (tmp_path / ".hecate/integrations/misp.json").read_text()


def test_misp_missing_url_is_not_probed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    s = settings(tmp_path)
    s.cti_provider = "misp"
    s.misp_api_key = "secret-misp-key"
    s.misp_base_url = None
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(503)

    result = check_integrations(s, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert not result["misp"]["healthy"]
    assert all(request.url.path != "/servers/getVersion" for request in requests)


@pytest.mark.parametrize("can_add,can_modify", [(True, True), (True, False), (False, True)])
def test_misp_downstream_checks_writer_separately_from_intake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, can_add: bool, can_modify: bool
) -> None:
    monkeypatch.chdir(tmp_path)
    s = settings(tmp_path)
    s.misp_publishing_enabled = True
    s.misp_base_url = "https://misp.test"
    s.misp_api_key = "intake-read-key"
    s.misp_output_api_key = "dedicated-write-key"
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "misp.test":
            seen.append(request)
            assert request.headers["Accept"] == "application/json"
            if request.url.path == "/users/view/me":
                assert request.headers["Authorization"] == "dedicated-write-key"
                return httpx.Response(
                    200, json={"Role": {"perm_add": can_add, "perm_modify": can_modify}}
                )
            assert request.headers["Authorization"] == "intake-read-key"
            return httpx.Response(200, json={"version": "2.5"})
        return httpx.Response(503)

    result = check_integrations(s, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert result["misp_output"]["enabled"]
    assert result["misp_output"]["healthy"] is (can_add and can_modify)
    assert not result["misp"]["enabled"]
    assert all(request.method == "GET" for request in seen)


def test_source_checks_are_read_only_and_do_not_establish_or_consume_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    s = settings(tmp_path)
    s.cti_provider = "lolbas"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            if "/commits/" in request.url.path:
                return httpx.Response(200, json={"sha": "a" * 40})
            return httpx.Response(
                200, json={"tree": [{"type": "blob", "path": "yml/Certutil.yml", "sha": "b"}]}
            )
        if request.url.host == "raw.githubusercontent.com":
            return httpx.Response(
                200,
                text="Name: Certutil.exe\nCommands:\n- Command: certutil.exe -urlcache -split -f {REMOTEURL}\n",
            )
        return httpx.Response(503)

    result = check_integrations(s, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert result["lolbas"]["healthy"]
    assert not (tmp_path / ".cursors").exists()


def test_structured_primary_evidence_uses_retained_literals_not_model_fetch(tmp_path: Path) -> None:
    provider = LolbasProvider(tmp_path)
    command = "certutil.exe -urlcache -split -f {REMOTEURL}"
    item = provider.build_item(
        {"Name": "Certutil.exe", "Commands": [{"Command": command}]},
        f"Commands:\n- Command: {command}",
        "yml/Certutil.yml",
        "a" * 40,
    )
    item.metadata["source_artifacts"].append({"value": "invented-command", "kind": "command_line"})
    hecate = MagicMock()
    orch = Orchestrator(
        settings=settings(tmp_path), hecate=hecate, cti_provider=provider, notify=MagicMock()
    )
    orch._gather_source_evidence(item)
    hecate.source_evidence.assert_not_called()
    assert isinstance(orch._source_evidence, SourceEvidence)
    assert [a.value for a in orch._source_evidence.artifacts] == [command]
    assert orch._source_evidence.text == item.content
    provider.close()


def test_request_template_is_not_deduplicated_just_because_a_kev_hunt_mentions_the_cve(
    tmp_path: Path,
) -> None:
    from hecate_runner.cti.base import CTIItem

    s = settings(tmp_path)
    s.hunts_root.mkdir(parents=True)
    hunt = s.hunts_root / "H-0001.md"
    hunt.write_text("Prior CVE inventory CVE-2024-3400\n[KEV](https://cisa.gov/kev)")
    item = CTIItem(
        source="nuclei",
        title="Nuclei CVE-2024-3400 request",
        content="Documented HTTP probe",
        source_url="https://github.com/templates/blob/pinned/template.yaml",
        metadata={"http_requests": [{"method": "PUT"}]},
    )
    orch = Orchestrator(
        settings=s, hecate=MagicMock(), cti_provider=MagicMock(), notify=MagicMock()
    )
    assert orch._drafted_from_same_source(item) is None
    hunt.write_text(hunt.read_text() + f"\n[Template]({item.source_url})")
    assert orch._drafted_from_same_source(item) == "H-0001"


def test_health_query_credentials_are_redacted_even_with_httpx_debug_logging(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from hecate_runner.integration_health import protect_request_logs

    protect_request_logs()
    with caplog.at_level(logging.DEBUG, logger="httpx"):
        logging.getLogger("httpx").info(
            "HTTP Request: %s", "https://api.shodan.io/api-info?key=do-not-log-this"
        )
    assert "do-not-log-this" not in caplog.text
    assert "key=[redacted]" in caplog.text
