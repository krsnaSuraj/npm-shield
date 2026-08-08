"""Tests for npm_shield.feed.ThreatFeed (offline mode — no network)."""
import pytest

from npm_shield.feed import ThreatFeed


@pytest.fixture
def feed(tmp_path, monkeypatch):
    """A ThreatFeed in offline mode with a hermetic cache dir."""
    monkeypatch.setenv("NPM_SHIELD_FEED_CACHE", str(tmp_path / "cache"))
    return ThreatFeed(offline_mode=True)


def test_load_campaign_meta(feed):
    """Campaign metadata loads from data/campaign_meta.json."""
    meta = feed.campaign_meta
    assert meta["campaign"]
    assert meta["verified"] is True
    assert "Shai-Hulud" in meta["campaign"]


def test_get_affected_packages(feed):
    """The local verified IOC set is exposed (keyv + specific versions)."""
    pkgs = feed.affected_packages()
    assert "keyv" in pkgs
    assert pkgs["keyv"] == ["6.0.0"]
    assert "@nebula.js/cli-build" in pkgs
    assert "7.1.2" in pkgs["@nebula.js/cli-build"]


def test_is_affected_exact(feed):
    assert feed.is_affected("keyv", "6.0.0") is True
    assert feed.is_affected("keyv", "5.6.0") is False
    assert feed.is_affected("lodash", "4.17.21") is False


def test_is_affected_specific_version(feed):
    """Only the exact poisoned versions match (no wildcards in v0.1.0 data)."""
    assert feed.is_affected("@nebula.js/cli-build", "7.1.2") is True
    assert feed.is_affected("@nebula.js/cli-build", "0.0.1") is False


def test_version_matches():
    assert ThreatFeed.version_matches("6.0.0", ["6.0.0"]) is True
    assert ThreatFeed.version_matches("6.0.1", ["6.0.0"]) is False
    assert ThreatFeed.version_matches("1.2.3", ["*"]) is True
    assert ThreatFeed.version_matches(None, ["*"]) is True
    assert ThreatFeed.version_matches(None, ["6.0.0"]) is False


def test_offline_update_returns_false(feed):
    """Offline mode never touches the network and reports no update."""
    assert feed.update() is False


def test_last_updated_none(feed):
    """No cache file exists yet, so last_updated is None."""
    assert feed.last_updated is None


def test_never_crashes(tmp_path, monkeypatch):
    """Feed construction and queries degrade gracefully."""
    monkeypatch.setenv("NPM_SHIELD_FEED_CACHE", str(tmp_path / "empty"))
    f = ThreatFeed(offline_mode=True)
    assert isinstance(f.get_affected_packages(), dict)
    assert f.update() is False
    assert f.last_updated is None
    assert f.is_affected("keyv", "6.0.0") is True
