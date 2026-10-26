from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import get_provider
from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.certstream import CertStreamCursorState, CertStreamProvider


@pytest.fixture
def certstream_provider(tmp_path: Path) -> CertStreamProvider:
    cursor_file = tmp_path / "certstream_cursor.json"
    return CertStreamProvider(
        cursor_file=cursor_file,
        stream_url="wss://certstream.calidog.io/",
        brand_patterns=["apple", "notion", "metamask", "binance"],
        suspicious_keywords=["download", "update", "login", "verify", "wallet", "app", "airdrop"],
        poll_timeout_sec=1.0,
    )


def test_matches_brand_protection_rules(certstream_provider: CertStreamProvider):
    # Suspicious brand + staging lures
    matched, brand, kws = certstream_provider.matches_brand_protection("download-notion-app.com")
    assert matched is True
    assert brand == "notion"
    assert "download" in kws
    assert "app" in kws

    matched, brand, kws = certstream_provider.matches_brand_protection("metamask-wallet-verify.net")
    assert matched is True
    assert brand == "metamask"
    assert "wallet" in kws
    assert "verify" in kws

    # Wildcard prefix
    matched, brand, kws = certstream_provider.matches_brand_protection(
        "*.apple-security-update.xyz"
    )
    assert matched is True
    assert brand == "apple"
    assert "update" in kws

    # Official legitimate domains must NOT be flagged
    assert certstream_provider.matches_brand_protection("apple.com")[0] is False
    assert certstream_provider.matches_brand_protection("support.apple.com")[0] is False
    assert certstream_provider.matches_brand_protection("notion.so")[0] is False
    assert certstream_provider.matches_brand_protection("www.notion.so")[0] is False

    # Unrelated domains
    assert certstream_provider.matches_brand_protection("regular-website.org")[0] is False

    # Brand without any staging / lure keywords
    assert certstream_provider.matches_brand_protection("apple-cider-farm.com")[0] is False


def test_process_certificate_event(certstream_provider: CertStreamProvider):
    event = {
        "message_type": "certificate_update",
        "data": {
            "cert_index": 987654,
            "leaf_cert": {
                "subject": {"CN": "notion-desktop-download.com"},
                "all_domains": [
                    "notion-desktop-download.com",
                    "*.notion-desktop-download.com",
                    "legitimate-blog.org",
                ],
                "issuer": {
                    "O": "Let's Encrypt",
                    "CN": "R3",
                },
            },
        },
    }

    items = certstream_provider.process_certificate_event(event)
    assert len(items) == 1
    item = items[0]

    assert item.source == "certstream"
    assert item.identifier == "certstream-notion-desktop-download.com"
    assert "notion-desktop-download.com" in item.title
    assert "https://crt.sh/?q=notion-desktop-download.com" in item.source_url
    assert item.metadata["domain"] == "notion-desktop-download.com"
    assert item.metadata["matched_brand"] == "notion"
    assert "download" in item.metadata["matched_keywords"]
    assert "Let's Encrypt" in item.content
    assert "Indicators (1 total): domain (1)" in item.content


def test_cursor_state_and_acknowledgement(certstream_provider: CertStreamProvider):
    cursor_file = certstream_provider.cursor_file
    assert not cursor_file.exists()

    item = CTIItem(
        content="Test content",
        source="certstream",
        identifier="certstream-apple-login-verify.top",
        metadata={"domain": "apple-login-verify.top"},
    )
    certstream_provider._items.append(item)

    # next_item retrieves it
    peeked = certstream_provider.next_item()
    assert peeked == item

    # acknowledge persists cursor and pops from buffer
    certstream_provider.acknowledge(item)
    assert certstream_provider.next_item() is None
    assert cursor_file.exists()

    # Re-reading from cursor verifies domain is recorded
    reloaded_cursor = CertStreamCursorState.from_file(cursor_file)
    assert "apple-login-verify.top" in reloaded_cursor.seen_domains

    # A duplicate event for this domain is filtered out
    dup_event = {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": ["apple-login-verify.top"],
                "issuer": {"O": "ZeroSSL"},
            }
        },
    }
    dup_items = certstream_provider.process_certificate_event(dup_event)
    assert len(dup_items) == 0


def test_get_provider_factory(tmp_path: Path):
    settings = Settings(
        hecate_workspace=tmp_path,
        cti_provider="certstream",
        certstream_stream_url="wss://certstream.calidog.io/",
        certstream_brand_patterns_raw="apple,notion,metamask",
        certstream_suspicious_keywords_raw="download,login,airdrop",
    )
    provider = get_provider("certstream", settings=settings)
    assert isinstance(provider, CertStreamProvider)
    assert provider.name == "certstream"
    assert "apple" in provider.brand_patterns
    assert "download" in provider.suspicious_keywords


@patch("websockets.sync.client.connect")
def test_poll_stream_success_and_error_handling(
    mock_connect, certstream_provider: CertStreamProvider
):
    # Mock WebSocket connection receiving one message
    mock_ws = MagicMock()
    mock_ws.recv.return_value = json.dumps(
        {
            "message_type": "certificate_update",
            "data": {
                "leaf_cert": {
                    "all_domains": ["binance-airdrop-claim.xyz"],
                    "issuer": {"O": "Google Trust Services"},
                }
            },
        }
    )
    mock_connect.return_value.__enter__.return_value = mock_ws

    certstream_provider._poll_stream(timeout_sec=0.5)
    assert len(certstream_provider._items) == 1
    assert certstream_provider._items[0].metadata["domain"] == "binance-airdrop-claim.xyz"

    # Test network failure does not crash provider
    mock_connect.side_effect = Exception("WebSocket network error")
    certstream_provider._poll_stream(timeout_sec=0.5)
    # Still retains buffered item
    assert len(certstream_provider._items) == 1


def test_certstream_buffer_file_lifecycle(tmp_path: Path):
    cursor_file = tmp_path / "certstream_cursor.json"
    buffer_file = tmp_path / "certstream_buffer.json"

    provider = CertStreamProvider(
        cursor_file=cursor_file,
        buffer_file=buffer_file,
        brand_patterns=["apple", "notion"],
        suspicious_keywords=["login", "download"],
        poll_timeout_sec=0.1,
    )

    # Stage an event using buffer_domain
    provider.buffer_domain(
        "notion-login-verify.com",
        brand="notion",
        keywords=["login"],
        issuer="Let's Encrypt",
    )
    assert buffer_file.exists()

    # next_item should read from buffer_file without opening websocket
    item = provider.next_item()
    assert item is not None
    assert item.identifier == "certstream-notion-login-verify.com"
    assert item.metadata["domain"] == "notion-login-verify.com"
    assert item.metadata["matched_brand"] == "notion"
    assert "login" in item.metadata["matched_keywords"]

    # Acknowledging should prune buffer_file and advance cursor
    provider.acknowledge(item)
    assert cursor_file.exists()
    reloaded_cursor = CertStreamCursorState.from_file(cursor_file)
    assert "notion-login-verify.com" in reloaded_cursor.seen_domains

    # Buffer file is now empty of this domain
    assert json.loads(buffer_file.read_text(encoding="utf-8")) == []

    # Subsequent poll returns None
    with patch.object(provider, "_poll_stream"):
        assert provider.next_item() is None


def test_certstream_buffer_raw_event(tmp_path: Path):
    cursor_file = tmp_path / "certstream_cursor.json"
    buffer_file = tmp_path / "certstream_buffer.json"

    provider = CertStreamProvider(
        cursor_file=cursor_file,
        buffer_file=buffer_file,
        brand_patterns=["apple"],
        suspicious_keywords=["download"],
        poll_timeout_sec=0.1,
    )

    raw_event = {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": ["apple-download-client.info"],
                "issuer": {"O": "DigiCert Inc"},
            }
        },
    }
    provider.buffer_event(raw_event)

    item = provider.next_item()
    assert item is not None
    assert item.metadata["domain"] == "apple-download-client.info"
    assert item.metadata["matched_brand"] == "apple"
    assert "download" in item.metadata["matched_keywords"]
