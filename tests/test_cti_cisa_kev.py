import pytest
from pathlib import Path
from datetime import datetime, timezone
import json
from unittest.mock import patch, MagicMock
from hecate_runner.cti.cisa_kev import CisaKevProvider

@pytest.fixture
def provider(tmp_path):
    return CisaKevProvider(workspace=tmp_path)

def test_read_cursor_no_file(provider):
    dt = provider._read_cursor()
    # should be roughly 7 days ago
    now = datetime.now(timezone.utc)
    assert (now - dt).days in (6, 7)

def test_read_cursor_with_file(provider):
    date_str = "2026-09-08T00:00:00+00:00"
    provider.cursor_file.parent.mkdir(parents=True, exist_ok=True)
    provider.cursor_file.write_text(json.dumps({"last_date_added": date_str}))
    dt = provider._read_cursor()
    assert dt.isoformat() == date_str

def test_write_cursor(provider):
    dt = datetime(2026, 9, 8, tzinfo=timezone.utc)
    provider._write_cursor(dt)
    assert json.loads(provider.cursor_file.read_text())["last_date_added"] == dt.isoformat()

@patch("urllib.request.urlopen")
def test_fetch_catalog_success(mock_urlopen, provider):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({
        "vulnerabilities": [
            {"cveID": "CVE-2", "dateAdded": "2026-09-02"},
            {"cveID": "CVE-1", "dateAdded": "2026-09-01"}
        ]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    vulns = provider._fetch_catalog()
    assert len(vulns) == 2
    # Should be sorted ascending
    assert vulns[0]["cveID"] == "CVE-1"
    assert vulns[1]["cveID"] == "CVE-2"

@patch("urllib.request.urlopen")
def test_next_item_yields_new(mock_urlopen, provider):
    # Set cursor to 2026-09-01
    provider._write_cursor(datetime(2026, 9, 1, tzinfo=timezone.utc))
    
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({
        "vulnerabilities": [
            {"cveID": "CVE-1", "dateAdded": "2026-09-01", "vendorProject": "A", "product": "B", "vulnerabilityName": "C", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2", "dateAdded": "2026-09-02", "vendorProject": "D", "product": "E", "vulnerabilityName": "F", "knownRansomwareCampaignUse": "Unknown"}
        ]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    item = provider.next_item()
    assert item is not None
    assert item.identifier == "CVE-2"
    assert "Tags: ransomware-campaign-use" not in item.content
    
    # Next item should be None because we haven't acknowledged
    # Wait, next_item() re-reads catalog from cache, then checks cursor. Since cursor hasn't moved, it yields CVE-2 again.
    item2 = provider.next_item()
    assert item2.identifier == "CVE-2"

def test_acknowledge(provider):
    from hecate_runner.cti.base import CTIItem
    dt = datetime(2026, 9, 9, tzinfo=timezone.utc)
    item = CTIItem(content="x", received_at=dt)
    provider.acknowledge(item)
    assert provider._read_cursor() == dt

