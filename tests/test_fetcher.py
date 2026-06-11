"""Tests for remote fetcher — URL parsing and SSRF guards, no real network calls."""

import shutil
import tempfile
from pathlib import Path

import pytest

import skill_audit.fetcher as fetcher_mod
from skill_audit.fetcher import (
    _clone_repo,
    _is_public_ip,
    _PinnedHTTPConnection,
    _validate_url_safe,
    cleanup_temp,
    is_remote,
)


class TestIsRemote:
    def test_https_url(self):
        assert is_remote("https://github.com/user/repo") is True

    def test_http_url(self):
        assert is_remote("http://example.com/skill.md") is True

    def test_local_path(self):
        assert is_remote("/home/user/.ai/skills/review.md") is False

    def test_relative_path(self):
        assert is_remote("./skills/review.md") is False

    def test_home_path(self):
        assert is_remote("~/skills/review.md") is False


class TestIsPublicIp:
    def test_public(self):
        assert _is_public_ip("8.8.8.8") is True

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",       # loopback
            "10.0.0.5",        # private
            "192.168.1.1",     # private
            "172.16.0.1",      # private
            "169.254.169.254", # link-local / cloud metadata
            "0.0.0.0",         # unspecified
            "::1",             # ipv6 loopback
            "fd00::1",         # ipv6 unique-local
        ],
    )
    def test_non_public(self, ip):
        assert _is_public_ip(ip) is False


class TestValidateUrlSafe:
    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "ext::sh -c whoami",
            "gopher://example.com/",
        ],
    )
    def test_rejects_non_http_schemes(self, url):
        with pytest.raises(ValueError, match="non-http"):
            _validate_url_safe(url)

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/admin",
            "http://localhost:8080/internal",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://[::1]/",
        ],
    )
    def test_rejects_non_public_hosts(self, url):
        with pytest.raises(ValueError, match="non-public|resolve"):
            _validate_url_safe(url)

    def test_missing_host(self):
        with pytest.raises(ValueError):
            _validate_url_safe("http:///nohost")


class TestCloneRepoHardening:
    def test_rejects_non_http_transport(self):
        with pytest.raises(ValueError, match="non-http"):
            _clone_repo("ext::sh -c 'curl evil'")

    def test_rejects_file_transport(self):
        with pytest.raises(ValueError, match="non-http"):
            _clone_repo("file:///tmp/evil")

    def test_rejects_leading_dash_url(self):
        with pytest.raises(ValueError, match="suspicious repo URL"):
            _clone_repo("--upload-pack=touch /tmp/pwned")

    def test_rejects_option_injection_branch(self):
        with pytest.raises(ValueError, match="suspicious branch"):
            _clone_repo("https://github.com/user/repo.git", branch="--upload-pack=x")


class TestConnectionPinning:
    """The DNS-rebinding fix: connections must target the pre-validated IP, not
    re-resolve the hostname at connect time."""

    def test_connect_uses_pinned_ip_not_hostname(self, monkeypatch):
        captured = {}

        def fake_create_connection(address, *args, **kwargs):
            captured["address"] = address
            raise OSError("short-circuit before real network I/O")

        monkeypatch.setattr(fetcher_mod.socket, "create_connection", fake_create_connection)
        conn = _PinnedHTTPConnection(
            "example.com", pinned_ip="203.0.113.7", port=80, timeout=5
        )
        with pytest.raises(OSError):
            conn.connect()
        # Connected to the validated IP, NOT a re-resolution of "example.com".
        assert captured["address"] == ("203.0.113.7", 80)


class TestCleanupTemp:
    def test_removes_only_our_temp_dir(self):
        tmp = Path(tempfile.mkdtemp(prefix="skill-audit-"))
        nested = tmp / "repo" / "skills"
        nested.mkdir(parents=True)
        # A sibling temp dir we did NOT target must survive — proves deletion is
        # scoped to the single resolved dir, not "anything skill-audit-*".
        sibling = Path(tempfile.mkdtemp(prefix="skill-audit-"))
        cleanup_temp(nested)
        assert not tmp.exists()
        assert sibling.exists()
        shutil.rmtree(sibling, ignore_errors=True)

    def test_ignores_unrelated_path(self, tmp_path):
        # A path that is not under a skill-audit- temp dir must not be deleted.
        target = tmp_path / "important"
        target.mkdir()
        cleanup_temp(target)
        assert target.exists()

    def test_ignores_prefixed_dir_outside_temp_root(self, tmp_path):
        # A `skill-audit-`-named dir whose parent is NOT the system temp root
        # must NOT be deleted — this is the guard that distinguishes a scoped
        # deletion from a name-prefix-only match.
        fake = tmp_path / "skill-audit-evil"
        child = fake / "child"
        child.mkdir(parents=True)
        cleanup_temp(child)
        assert fake.exists()
