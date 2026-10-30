"""Explicit read-only connectivity checks used by the monitor and daemon.

No notifications, hunts, detonation, or template execution are performed.
A configured credential alone never confirms an integration.
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx
from dotenv import dotenv_values

from hecate_runner.config import Settings
from hecate_runner.integration_health import protect_request_logs, record_health


def check_integrations(settings: Settings, *, client: httpx.Client | None = None) -> dict[str, Any]:
    protect_request_logs()
    env = {
        **dotenv_values(settings.hecate_workspace / ".env"),
        **dotenv_values(".env"),
        **os.environ,
    }
    active = set(
        settings.cti_multi_provider_names
        if settings.cti_provider == "multi"
        else [settings.cti_provider]
    )
    # Keys are the stable integration IDs consumed by Core's monitor.
    probes: dict[str, tuple[bool, str, str, dict[str, str], Any]] = {}
    configured_probes: dict[str, bool] = {}

    def add(
        name: str,
        url: str,
        *,
        enabled: bool = True,
        configured: bool | None = None,
        key: str = "",
        header: str = "",
        method: str = "GET",
        body: Any = None,
    ) -> None:
        probes[name] = (enabled, method, url, {header: key} if header and key else {}, body)
        configured_probes[name] = enabled if configured is None else configured

    def token(*names: str) -> str:
        return next((str(env[n]) for n in names if env.get(n)), "")

    llm_provider = settings.hecate_llm_provider or token("HECATE_LLM_PROVIDER") or "ollama"
    llm_model = settings.hecate_llm_model or token("HECATE_LLM_MODEL")
    add(
        "llm",
        (token("OLLAMA_HOST") or "http://localhost:11434").rstrip("/") + "/api/tags",
        enabled=llm_provider == "ollama",
    )
    if llm_provider != "ollama":
        if llm_provider == "openai":
            key = token("OPENAI_API_KEY")
            add(
                "llm",
                "https://api.openai.com/v1/models",
                enabled=bool(key),
                key="Bearer " + key,
                header="Authorization",
            )
        elif llm_provider == "anthropic":
            key = token("ANTHROPIC_API_KEY")
            add(
                "llm",
                "https://api.anthropic.com/v1/models",
                enabled=bool(key),
                key=key,
                header="x-api-key",
            )
        else:
            add("llm", "", enabled=True)
    if probes["llm"][2].endswith(":11434"):
        p = probes["llm"]
        probes["llm"] = (p[0], p[1], p[2] + "/api/tags", p[3], p[4])
    tavily = token("TAVILY_API_KEY")
    add(
        "tavily",
        "https://api.tavily.com/search",
        enabled=bool(tavily),
        method="POST",
        body={"api_key": tavily, "query": "cybersecurity advisory", "max_results": 1},
    )
    add(
        "otx",
        "https://otx.alienvault.com/api/v1/user/me",
        enabled="otx" in active and bool(settings.otx_api_key),
        configured=bool(settings.otx_api_key),
        key=settings.otx_api_key or "",
        header="X-OTX-API-KEY",
    )
    add(
        "misp",
        str(settings.misp_base_url or "") + "/servers/getVersion",
        enabled="misp" in active and bool(settings.misp_base_url and settings.misp_api_key),
        configured=bool(settings.misp_base_url and settings.misp_api_key),
        key=settings.misp_api_key or "",
        header="Authorization",
    )
    misp_writer = settings.misp_output_api_key or settings.misp_api_key
    add(
        "misp_output",
        str(settings.misp_base_url or "").rstrip("/") + "/users/view/me",
        enabled=settings.misp_publishing_enabled,
        configured=settings.misp_publishing_enabled
        and bool(settings.misp_base_url and misp_writer),
        key=misp_writer or "",
        header="Authorization",
    )
    add(
        "vt",
        "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
        enabled=bool(settings.vt_api_key),
        key=settings.vt_api_key or "",
        header="x-apikey",
    )
    add(
        "greynoise",
        "https://api.greynoise.io/v3/community/1.1.1.1",
        enabled=bool(settings.greynoise_api_key),
        key=settings.greynoise_api_key or "",
        header="key",
    )
    for name, url, keys, header in [
        (
            "abuseipdb",
            "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1",
            ("ABUSEIPDB_API_KEY",),
            "Key",
        ),
        ("shodan", "https://api.shodan.io/api-info?key=", ("SHODAN_API_KEY",), ""),
        (
            "censys",
            "https://api.platform.censys.io/v3/global/asset/host/1.1.1.1",
            ("CENSYS_API_TOKEN",),
            "Authorization",
        ),
        (
            "urlscan",
            "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1",
            ("URLSCAN_API_KEY",),
            "API-Key",
        ),
        (
            "hybrid",
            "https://www.hybrid-analysis.com/api/v2/key/current",
            ("HYBRID_ANALYSIS_API_KEY", "HA_API_KEY"),
            "api-key",
        ),
        ("spur", "https://api.spur.us/v2/context/1.1.1.1", ("SPUR_API_KEY",), "Token"),
        (
            "tor_proxy",
            "https://ipinfo.io/1.1.1.1/json?token=",
            ("IPINFO_TOKEN", "IPINFO_API_KEY"),
            "",
        ),
        (
            "vulncheck",
            "https://api.vulncheck.com/v3/index/vulncheck-kev?limit=1",
            ("VULNCHECK_API_KEY",),
            "Authorization",
        ),
        (
            "triage",
            "https://api.tria.ge/v0/samples?limit=1",
            ("TRIAGE_API_KEY", "HATCHING_TRIAGE_API_KEY"),
            "Authorization",
        ),
    ]:
        key = token(*keys)
        if header == "Authorization" and key:
            key = "Bearer " + key
        if url.endswith("="):
            url += key
        add(
            name,
            url,
            enabled=bool(key)
            and (
                name not in {"censys", "vulncheck", "triage"}
                or {"censys": "censys_c2"}.get(name, name) in active
            ),
            key=key,
            header=header,
            configured=bool(key),
        )
    abuse = settings.abusech_api_key or ""
    for name, url, body in [
        ("threatfox", "https://threatfox-api.abuse.ch/api/v1/", {"query": "get_iocs", "days": 1}),
        (
            "malwarebazaar",
            "https://mb-api.abuse.ch/api/v1/",
            {"query": "get_recent", "selector": "time"},
        ),
        ("urlhaus", "https://urlhaus-api.abuse.ch/v1/urls/recent/", None),
    ]:
        add(
            name,
            url,
            enabled=bool(abuse),
            key=abuse,
            header="Auth-Key",
            method="POST" if body else "GET",
            body=body,
        )
    for name, url in [
        ("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"),
        ("sslbl", "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"),
        ("rdap", "https://rdap.org/domain/example.com"),
        ("crtsh", "https://crt.sh/?q=example.com&output=json"),
        ("epss", "https://api.first.org/data/v1/epss?cve=CVE-2024-3400"),
        ("osv", "https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q"),
        (
            "cisa_kev",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ),
        ("first_org", "https://api.first.org/data/v1/epss?limit=1"),
        ("msrc", settings.msrc_updates_url),
        ("dfir_report", settings.dfir_report_feed_url),
        ("anyrun", settings.anyrun_feed_url),
        ("rss", settings.rss_feed_urls[0] if settings.rss_feed_urls else ""),
        ("github_poc", "https://api.github.com/repos/projectdiscovery/nuclei-templates"),
        ("vxunderground", "https://api.github.com/repos/vxunderground/VXUG-Papers"),
        ("cisa_narrative", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ]:
        source_names = {
            "cisa_kev",
            "first_org",
            "msrc",
            "dfir_report",
            "anyrun",
            "rss",
            "github_poc",
            "vxunderground",
        }
        enabled = name not in source_names or name in active
        if name == "cisa_narrative":
            enabled = "cisa_advisories" in active
        add(name, url, enabled=enabled, configured=bool(url))
    slack = token("SLACK_BOT_TOKEN")
    add(
        "slack",
        "https://slack.com/api/auth.test",
        enabled=bool(slack),
        key="Bearer " + slack if slack else "",
        header="Authorization",
    )
    add(
        "cloud_threat",
        settings.cloud_threat_feed_urls[0] if settings.cloud_threat_feed_urls else "",
        enabled="cloud_threat" in active,
        configured=bool(settings.cloud_threat_feed_urls),
    )
    if settings.opencti_url and settings.opencti_token:
        add(
            "opencti",
            settings.opencti_url.rstrip("/") + "/graphql",
            enabled="opencti" in active,
            configured=True,
            method="POST",
            key="Bearer " + settings.opencti_token,
            header="Authorization",
            body={"query": "query IntegrationHealth { about { version } }"},
        )
    if not (settings.opencti_url and settings.opencti_token):
        add("opencti", "", enabled="opencti" in active)
    add(
        "shadowserver",
        "https://transform.shadowserver.org/api2/reports/list",
        enabled="shadowserver" in active
        and bool(settings.shadowserver_api_key and settings.shadowserver_api_secret),
        configured=bool(settings.shadowserver_api_key and settings.shadowserver_api_secret),
        method="POST",
        body={"apikey": settings.shadowserver_api_key, "secret": settings.shadowserver_api_secret},
    )
    add(
        "pdns",
        "https://api.mnemonic.no/pdns/v3/example.com?limit=1",
        key=token("MNEMONIC_API_KEY"),
        header="Argus-API-Key",
    )

    def run(pair: tuple[str, Any]) -> tuple[str, Any]:
        name, (enabled, method, url, headers, body) = pair
        if not configured_probes[name]:
            return name, record_health(
                settings.hecate_workspace, name, False, "disabled or unconfigured", enabled=False
            )
        if not url:
            return name, record_health(
                settings.hecate_workspace,
                name,
                False,
                "instance unconfigured; fallback is test data"
                if name == "opencti"
                else "no confirmed read-only probe",
                enabled=enabled,
            )
        own = client is None
        c = client or httpx.Client(
            timeout=8,
            follow_redirects=True,
            verify=settings.misp_verify_ssl if name in {"misp", "misp_output"} else True,
        )
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 Hecate-Integration-Check",
                "Accept": "application/json, application/xml, text/plain",
                **headers,
            }
            if name in {"misp", "misp_output"}:
                headers["Accept"] = "application/json"
            if name == "cisa_narrative":
                from hecate_runner.cti.cisa_advisories import BROWSER_UA

                headers["User-Agent"] = BROWSER_UA
            if name == "llm" and llm_provider == "anthropic":
                headers["anthropic-version"] = "2023-06-01"
            r = (
                c.request(method, url, headers=headers, json=body)
                if name != "malwarebazaar"
                else c.post(url, headers=headers, data=body)
            )
            r.raise_for_status()
            if not r.content:
                raise ValueError("empty response")
            if name == "opencti" and (
                r.json().get("errors") or not r.json().get("data", {}).get("about")
            ):
                raise ValueError("GraphQL authentication or schema rejected")
            if name == "slack" and not r.json().get("ok"):
                raise ValueError("authentication rejected")
            if name == "misp_output":
                identity = r.json()
                role = identity.get("Role") or identity.get("User", {}).get("Role", {})
                if not all(
                    role.get(permission) in (True, 1, "1")
                    for permission in ("perm_add", "perm_modify")
                ):
                    raise ValueError("writer permissions unavailable")
            if name == "llm" and llm_provider == "ollama":
                models = [m.get("name") for m in r.json().get("models", [])]
                if not models or (llm_model and llm_model not in models):
                    raise ValueError("configured model unavailable")
            if name in {"rss", "cisa_narrative", "dfir_report", "cloud_threat"}:
                import feedparser

                if not feedparser.parse(r.content).entries:
                    raise ValueError("feed has no valid entries")
            if name == "pdns" and not isinstance(r.json().get("data"), list):
                raise ValueError("invalid passive DNS schema")
            if (
                name == "shadowserver"
                and not isinstance(r.json(), list)
                and not any(isinstance(r.json().get(k), list) for k in ("reports", "data"))
            ):
                raise ValueError("invalid reports schema")
            if name in {"epss", "first_org"} and not isinstance(r.json().get("data"), list):
                raise ValueError("invalid EPSS schema")
            if name == "cisa_kev" and not isinstance(r.json().get("vulnerabilities"), list):
                raise ValueError("invalid KEV schema")
            if name in {"feodo", "crtsh"} and not isinstance(r.json(), list):
                raise ValueError("invalid list schema")
            if name in {"threatfox", "malwarebazaar"} and r.json().get("query_status") not in {
                "ok",
                "no_result",
                "no_results",
            }:
                raise ValueError("query authentication or schema rejected")
            if name == "tavily" and "results" not in r.json():
                raise ValueError("invalid search response")
            if r.headers.get("content-type", "").startswith("text/html") and name not in {
                "dfir_report",
                "anyrun",
            }:
                raise ValueError("unexpected HTML response")
            return name, record_health(
                settings.hecate_workspace,
                name,
                True,
                "writer authenticated; create/modify permitted"
                if name == "misp_output"
                else "read-only endpoint confirmed",
                enabled=enabled,
            )
        except Exception as exc:
            detail = (
                f"HTTP {exc.response.status_code}"
                if isinstance(exc, httpx.HTTPStatusError)
                else type(exc).__name__
            )
            return name, record_health(
                settings.hecate_workspace, name, False, detail, enabled=enabled
            )
        finally:
            if own:
                c.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(pool.map(run, probes.items()))
    certstream_enabled = "certstream" in active
    if client is not None:
        results["certstream"] = record_health(
            settings.hecate_workspace,
            "certstream",
            False,
            "websocket not checked by HTTP transport",
            enabled=certstream_enabled,
        )
    else:
        try:
            from websockets.sync.client import connect

            with connect(settings.certstream_stream_url, open_timeout=5, close_timeout=1) as socket:
                message = json.loads(socket.recv(timeout=5))
                if message.get("message_type") not in {"heartbeat", "certificate_update"}:
                    raise ValueError("invalid CertStream message")
            results["certstream"] = record_health(
                settings.hecate_workspace,
                "certstream",
                True,
                "live websocket protocol confirmed",
                enabled=certstream_enabled,
            )
        except Exception as exc:
            results["certstream"] = record_health(
                settings.hecate_workspace,
                "certstream",
                False,
                type(exc).__name__,
                enabled=certstream_enabled,
            )
    # Check immutable sample schemas without advancing or acknowledging intake cursors.
    from hecate_runner.cti import get_provider
    from hecate_runner.cti.attack_deltas import AttackDeltaProvider
    from hecate_runner.cti.catalogs import LolDriversProvider
    from hecate_runner.cti.github_delta import GitHubDeltaProvider

    for name in (
        "lolbas",
        "loldrivers",
        "gtfobins",
        "nuclei",
        "cisa_advisories",
        "cisa_ics",
        "attack_deltas",
    ):
        provider = get_provider(name, settings=settings)
        assert isinstance(provider, (GitHubDeltaProvider, AttackDeltaProvider))
        if client is not None:
            provider.close()
            provider.client = client
            provider.owns_client = False
        try:
            if isinstance(provider, GitHubDeltaProvider):
                head = provider.get_json(f"repos/{provider.repo}/commits/{provider.branch}")
                revision = str(head["sha"])
                tree = provider.get_json(f"repos/{provider.repo}/git/trees/{revision}?recursive=1")
                if tree.get("truncated"):
                    raise ValueError("truncated repository tree")
                path = next(
                    v["path"]
                    for v in tree["tree"]
                    if v.get("type") == "blob" and provider.relevant(v["path"])
                )
                raw, data = provider.fetch_entry(revision, path)
                if name == "nuclei":
                    if not data.get("info") or not data.get("http"):
                        raise ValueError("invalid HTTP template sample")
                else:
                    sample = provider.build_item(data, raw, path, revision)
                    if (
                        isinstance(provider, LolDriversProvider)
                        and sample
                        and sample.metadata.get("sha256")
                    ):
                        provider.enrich(sample.metadata["sha256"][0])
            else:
                c = client or httpx.Client(timeout=15)
                try:
                    r = c.get(
                        "https://api.github.com/repos/mitre-attack/attack-stix-data/commits/master"
                    )
                    r.raise_for_status()
                    if len(r.json()["sha"]) != 40:
                        raise ValueError("invalid ATT&CK revision")
                finally:
                    if client is None:
                        c.close()
            results[name] = record_health(
                settings.hecate_workspace,
                name,
                True,
                "upstream repository/schema confirmed",
                enabled=name in active,
            )
        except Exception:
            results[name] = record_health(
                settings.hecate_workspace,
                name,
                False,
                "source fetch/schema check failed",
                enabled=name in active,
            )
        finally:
            provider.close()
    return results


def maybe_check_integrations(settings: Settings) -> None:
    stamp = settings.hecate_workspace / ".hecate" / "integrations" / "last-refresh"
    if stamp.exists() and time.time() - stamp.stat().st_mtime < 3600:
        return
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.touch()
    check_integrations(settings)


_refresh_thread = None


def start_health_refresh(settings: Settings) -> None:
    """Refresh off the polling path so slow services cannot delay hunt intake."""
    global _refresh_thread
    from threading import Thread

    stamp = settings.hecate_workspace / ".hecate" / "integrations" / "last-refresh"
    if _refresh_thread is not None and _refresh_thread.is_alive():
        return
    if stamp.exists() and time.time() - stamp.stat().st_mtime < 3600:
        return
    _refresh_thread = Thread(
        target=maybe_check_integrations, args=(settings,), daemon=True, name="integration-health"
    )
    _refresh_thread.start()
