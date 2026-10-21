"""Unit tests for GitHub PoC Monitor CTI provider."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import get_provider
from hecate_runner.cti.github_poc import (
    GitHubPocCursorState,
    GitHubPocProvider,
)


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True)
    return ws


def test_github_poc_cursor_persistence(temp_workspace: Path) -> None:
    cursor_file = temp_workspace / ".cursors" / "github_poc_cursor.json"
    state = GitHubPocCursorState.from_file(cursor_file)
    assert state.seen_repos == []

    state.record_repo("vuln-researcher/cve-2026-1234-poc", cursor_file)
    assert cursor_file.exists()

    reloaded = GitHubPocCursorState.from_file(cursor_file)
    assert "vuln-researcher/cve-2026-1234-poc" in reloaded.seen_repos

    # Record duplicate
    reloaded.record_repo("vuln-researcher/cve-2026-1234-poc", cursor_file)
    assert len(reloaded.seen_repos) == 1


def test_github_poc_search_api_parsing(temp_workspace: Path) -> None:
    provider = GitHubPocProvider(workspace=temp_workspace)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {
                "full_name": "attacker/CVE-2026-8888-rce",
                "html_url": "https://github.com/attacker/CVE-2026-8888-rce",
                "description": "Functional RCE exploit for CVE-2026-8888 in Apache Solr",
                "stargazers_count": 5,
                "updated_at": "2026-10-21T02:00:00Z",
            },
            {
                "full_name": "boring/non-cve-repo",
                "html_url": "https://github.com/boring/non-cve-repo",
                "description": "Just some random code",
                "stargazers_count": 0,
            },
        ]
    }

    with patch("httpx.get", return_value=mock_resp):
        candidates = provider._fetch_from_search_api()
        assert len(candidates) == 1
        cand = candidates[0]
        assert cand["full_name"] == "attacker/CVE-2026-8888-rce"
        assert "CVE-2026-8888" in cand["cves"]
        assert cand["stars"] == 5


def test_github_poc_search_api_rate_limit_fallback(temp_workspace: Path) -> None:
    provider = GitHubPocProvider(workspace=temp_workspace)

    r403 = MagicMock(status_code=403)
    r_curated = MagicMock(status_code=200)
    r_curated.text = (
        "### CVE-2026-5555 (2026-10-20)\n"
        "<code>Remote code execution flaw in Ivanti Connect Secure</code>\n"
        "- [exploit-author/ivanti-poc](https://github.com/exploit-author/ivanti-poc)\n"
    )

    def fake_get(url, *args, **kwargs):
        if "api.github.com/search" in url:
            return r403
        elif "raw.githubusercontent.com" in url:
            return r_curated
        return MagicMock(status_code=404)

    with patch("httpx.get", side_effect=fake_get):
        candidates = provider._fetch_from_search_api()
        assert len(candidates) == 1
        assert candidates[0]["full_name"] == "exploit-author/ivanti-poc"
        assert candidates[0]["cves"] == ["CVE-2026-5555"]


def test_extract_poc_artifacts_and_blurb(temp_workspace: Path) -> None:
    provider = GitHubPocProvider(workspace=temp_workspace)

    repo_data = {
        "full_name": "rapid7/CVE-2026-7777-poc",
        "html_url": "https://github.com/rapid7/CVE-2026-7777-poc",
        "description": "Proof of concept exploit for CVE-2026-7777 authentication bypass in FortiOS",
        "stars": 12,
    }

    readme = """
# CVE-2026-7777 FortiOS Exploit

This vulnerability allows unauthenticated attackers to achieve Remote Code Execution.

## Usage

```bash
python3 exploit.py -u https://target:8443/api/v2/cmdb -c id
```

Target port is 8443.
    """

    artifacts = provider._extract_poc_artifacts(repo_data, readme)
    assert artifacts["cve"] == "CVE-2026-7777"
    assert "Remote Code Execution" in artifacts["vuln_type"]
    assert len(artifacts["commands"]) >= 1
    assert "python3 exploit.py" in artifacts["commands"][0]
    assert "8443" in artifacts["ports"]

    blurb = provider._build_blurb(repo_data, artifacts)
    assert "Title: Proof-of-Concept Exploit Weaponization: CVE-2026-7777" in blurb
    assert "Source: GitHub PoC Monitor (rapid7/CVE-2026-7777-poc)" in blurb
    assert "python3 exploit.py" in blurb
    assert "T1190 (Exploit Public-Facing Application)" in blurb


def test_next_item_and_acknowledge(temp_workspace: Path) -> None:
    provider = GitHubPocProvider(workspace=temp_workspace)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {
                "full_name": "sec-team/CVE-2026-9001-exploit",
                "html_url": "https://github.com/sec-team/CVE-2026-9001-exploit",
                "description": "LPE exploit for CVE-2026-9001 in Linux Kernel",
                "stargazers_count": 3,
                "updated_at": "2026-10-21T03:00:00Z",
            }
        ]
    }

    mock_readme = MagicMock()
    mock_readme.status_code = 200
    mock_readme.json.return_value = {
        "content": "IyBFeHBsb2l0CgpgLi9wb2MgLS1lc2NhbGF0ZQpg"  # "# Exploit\n`./poc --escalate`"
    }

    def fake_get(url, *args, **kwargs):
        if "api.github.com/search" in url:
            return mock_resp
        elif "api.github.com/repos" in url and "readme" in url:
            return mock_readme
        return MagicMock(status_code=404)

    with patch("httpx.get", side_effect=fake_get):
        item = provider.next_item()
        assert item is not None
        assert item.source == "github_poc"
        assert item.identifier == "sec-team/CVE-2026-9001-exploit"
        assert item.metadata["cve_id"] == "CVE-2026-9001"

        # Acknowledge the item
        provider.acknowledge(item)

        # Calling next_item again should return None because it is now seen
        assert provider.next_item() is None


def test_get_provider_factory(temp_workspace: Path) -> None:
    settings = Settings(
        hecate_workspace=temp_workspace,
        cti_provider="github_poc",
        github_token="ghp_test12345",
    )
    p = get_provider("github_poc", settings=settings)
    assert isinstance(p, GitHubPocProvider)
    assert p.github_token == "ghp_test12345"
