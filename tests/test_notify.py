"""Unit tests for notify.py."""

import json
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from notify import _issue_body, _load_items


class TestLoadItems:
    """Tests for _load_items() function."""

    def test_load_items_from_dict_with_items_key(self, tmp_path: Path):
        """Load items from {"items": [...]} format."""
        data = {
            "meta": {"generated": "2024-01-01"},
            "items": [
                {"cve_id": "CVE-2024-0001"},
                {"cve_id": "CVE-2024-0002"},
            ],
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))
        items = _load_items(path)
        assert len(items) == 2
        assert items[0]["cve_id"] == "CVE-2024-0001"

    def test_load_items_from_list(self, tmp_path: Path):
        """Load items from raw list format."""
        data = [
            {"cve_id": "CVE-2024-0001"},
            {"cve_id": "CVE-2024-0002"},
        ]
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))
        items = _load_items(path)
        assert len(items) == 2

    def test_load_items_empty(self, tmp_path: Path):
        """Empty data returns empty list."""
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({"items": []}))
        items = _load_items(path)
        assert items == []


class TestIssueBody:
    """Tests for _issue_body() function."""

    def test_critical_priority_label(self, sample_radar_item: Dict[str, Any]):
        """Critical items should show CRITICAL priority."""
        body = _issue_body(sample_radar_item)
        assert "Priority: CRITICAL" in body

    def test_non_critical_priority_label(self, sample_radar_item: Dict[str, Any]):
        """Non-critical items should show ALERT priority."""
        item = {**sample_radar_item, "is_critical": False}
        body = _issue_body(item)
        assert "Priority: ALERT" in body

    def test_cve_id_in_body(self, sample_radar_item: Dict[str, Any]):
        """CVE ID should be in the body."""
        body = _issue_body(sample_radar_item)
        assert "CVE-2024-12345" in body

    def test_signals_section(self, sample_radar_item: Dict[str, Any]):
        """Signals section should show all flags."""
        body = _issue_body(sample_radar_item)
        assert "PatchThis: yes" in body
        assert "Watchlist: yes" in body
        assert "CISA KEV: yes" in body

    def test_epss_formatting(self, sample_radar_item: Dict[str, Any]):
        """EPSS should be formatted to 3 decimal places."""
        body = _issue_body(sample_radar_item)
        assert "EPSS: 0.850" in body

    def test_cvss_formatting(self, sample_radar_item: Dict[str, Any]):
        """CVSS should be formatted to 1 decimal place."""
        body = _issue_body(sample_radar_item)
        assert "CVSS: 9.8" in body

    def test_kev_due_date(self, sample_radar_item: Dict[str, Any]):
        """KEV due date should be shown when available."""
        body = _issue_body(sample_radar_item)
        assert "KEV Due Date: 2024-07-01" in body

    def test_cve_org_link(self, sample_radar_item: Dict[str, Any]):
        """CVE.org link should be included."""
        body = _issue_body(sample_radar_item)
        assert "https://www.cve.org/CVERecord?id=CVE-2024-12345" in body

    def test_description_included(self, sample_radar_item: Dict[str, Any]):
        """Description should be in body."""
        body = _issue_body(sample_radar_item)
        assert "A critical vulnerability" in body

    def test_missing_optional_fields(self):
        """Handle items with missing optional fields gracefully."""
        minimal = {
            "cve_id": "CVE-2024-00001",
            "is_critical": False,
        }
        body = _issue_body(minimal)
        assert "CVE-2024-00001" in body
        assert "Priority: ALERT" in body

    def test_none_epss_cvss(self):
        """Handle None values for EPSS and CVSS."""
        item = {
            "cve_id": "CVE-2024-00001",
            "probability_score": None,
            "cvss_score": None,
            "is_critical": False,
        }
        body = _issue_body(item)
        # Should not crash, just show empty
        assert "EPSS:" in body
        assert "CVSS:" in body


class TestDiscordPayload:
    """Tests for Discord notification formatting."""

    def test_discord_alert_structure(self, sample_radar_item: Dict[str, Any]):
        """Test Discord embed structure (without actually sending)."""
        # Import the function
        from notify import send_discord_alert

        # Mock requests.post
        with patch("notify.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            send_discord_alert("https://fake.webhook.url", sample_radar_item)

            # Verify it was called
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")

            # Check embed structure
            assert "embeds" in payload
            embed = payload["embeds"][0]
            assert "CVE-2024-12345" in embed["title"]
            assert "CRITICAL" in embed["title"]
            assert embed["color"] == 0xFF0000  # Red for critical

    def test_discord_summary_structure(self, sample_radar_item: Dict[str, Any]):
        """Test Discord summary embed structure."""
        from notify import send_discord_summary

        with patch("notify.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            items = [sample_radar_item]
            send_discord_summary("https://fake.webhook.url", items, "test/repo")

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")

            embed = payload["embeds"][0]
            assert "Summary" in embed["title"]
            assert any("Critical" in f["name"] for f in embed["fields"])


class TestSlackPayload:
    """Tests for Slack notification formatting."""

    def test_slack_alert_structure(self, sample_radar_item: Dict[str, Any]):
        """Test Slack message structure."""
        from notify import send_slack_alert

        with patch("notify.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            send_slack_alert("https://hooks.slack.com/fake", sample_radar_item)

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")

            assert "attachments" in payload
            assert payload["attachments"][0]["color"] == "danger"


class TestTeamsPayload:
    """Tests for Teams notification formatting."""

    def test_teams_alert_structure(self, sample_radar_item: Dict[str, Any]):
        """Test Teams Adaptive Card structure."""
        from notify import send_teams_alert

        with patch("notify.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_response

            send_teams_alert("https://teams.webhook.url", sample_radar_item)

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")

            assert payload["type"] == "message"
            assert "attachments" in payload
            card = payload["attachments"][0]["content"]
            assert card["type"] == "AdaptiveCard"
            assert card["version"] == "1.4"
