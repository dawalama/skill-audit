"""Fetch skills from remote sources (GitHub repos, raw URLs) for auditing.

Supports:
- GitHub repo URLs → git clone to temp dir
- GitHub blob URLs → convert to raw URL and fetch single file
- Raw URLs → fetch single .md file

Security: this is an auditing tool that fetches URLs the user (or an untrusted
skill) may not control. All file fetches go through SSRF protection that rejects
non-public addresses (loopback, link-local/metadata, private, reserved), then
*pin the connection to the validated IP* so a hostname cannot rebind to a
private/metadata address between validation and connect (DNS-rebinding/TOCTOU).
Redirects are re-validated and re-pinned per hop, responses are size-capped, and
git is restricted to http(s) transports only.
"""

import http.client
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlparse

_ALLOWED_SCHEMES = {"http", "https"}
# Cap remote reads so a hostile endpoint can't exhaust memory.
MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB
_MAX_REDIRECTS = 5
_REDIRECT_CODES = {301, 302, 303, 307, 308}


def is_remote(path: str) -> bool:
    """Check if a path is a remote URL."""
    return path.startswith(("https://", "http://"))


def _is_public_ip(ip_str: str) -> bool:
    """True only for globally-routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local  # covers 169.254.0.0/16 cloud metadata
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_url_safe(url: str) -> str:
    """Resolve a URL's host and return a validated, globally-routable IP.

    Rejects any host that resolves to a non-public address (loopback, RFC1918,
    169.254.169.254 cloud metadata, reserved, …). Returns the specific IP the
    caller MUST connect to — connecting to this pinned IP (rather than letting
    the HTTP stack re-resolve the hostname) is what closes the DNS-rebinding /
    TOCTOU hole: validation and connection then target the same address.
    """
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Refusing to fetch non-http(s) URL: {url}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"URL has no host: {url}")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host {host!r}: {e}") from e

    pinned_ip = None
    for info in infos:
        ip = str(info[4][0])
        if not _is_public_ip(ip):
            raise ValueError(
                f"Refusing to fetch {host!r}: resolves to non-public address "
                f"{ip} (SSRF / metadata-endpoint protection)"
            )
        if pinned_ip is None:
            pinned_ip = ip
    if pinned_ip is None:  # pragma: no cover - getaddrinfo returned nothing
        raise ValueError(f"Cannot resolve host {host!r}")
    return pinned_ip


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects to a pre-validated IP instead of
    re-resolving the hostname (defeats DNS rebinding)."""

    def __init__(self, host, *, pinned_ip, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects to a pre-validated IP while still using the
    original hostname for SNI and certificate verification."""

    def __init__(self, host, *, pinned_ip, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host
        # wrap_socket with the real hostname → SNI + cert hostname check use the
        # domain, not the pinned IP, so TLS still authenticates correctly.
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


def _open_pinned(url: str, pinned_ip: str, timeout: int) -> http.client.HTTPResponse:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"URL has no host: {url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
            host, pinned_ip=pinned_ip, port=port, timeout=timeout
        )
    else:
        conn = _PinnedHTTPConnection(
            host, pinned_ip=pinned_ip, port=port, timeout=timeout
        )
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    conn.request("GET", path, headers={"User-Agent": "skill-audit", "Host": host})
    return conn.getresponse()


def _safe_urlopen(url: str, timeout: int = 30) -> http.client.HTTPResponse:
    """Open `url` with SSRF protection and connection pinning.

    Each hop (initial request and every redirect) is independently resolved,
    validated, and connected to the validated IP, so a hostname cannot rebind to
    a private/metadata address between validation and connection.
    """
    for _ in range(_MAX_REDIRECTS + 1):
        pinned_ip = _validate_url_safe(url)
        resp = _open_pinned(url, pinned_ip, timeout)
        if resp.status in _REDIRECT_CODES:
            location = resp.headers.get("Location")
            resp.read()
            resp.close()
            if not location:
                raise ValueError(f"Redirect with no Location header: {url}")
            url = urljoin(url, location)
            continue
        return resp
    raise ValueError(f"Too many redirects fetching {url}")


def fetch_remote(url: str) -> tuple[Path, bool]:
    """Fetch a remote skill source to a local temp path.

    Returns (local_path, is_temp) where is_temp indicates the caller
    should clean up the path when done.

    Handles:
    - GitHub repo: https://github.com/user/repo → clones to temp dir
    - GitHub blob: https://github.com/user/repo/blob/main/SKILL.md → fetches raw file
    - GitHub tree: https://github.com/user/repo/tree/main/skills → clones + extracts subdir
    - Raw URL: https://example.com/skill.md → fetches to temp file
    """
    # GitHub blob URL → convert to raw and fetch single file
    blob_match = re.match(
        r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)",
        url,
    )
    if blob_match:
        owner, repo, branch, filepath = blob_match.groups()
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filepath}"
        return _fetch_raw_file(raw_url, filepath.split("/")[-1])

    # GitHub tree URL → clone repo, return subdirectory
    tree_match = re.match(
        r"https://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.*)",
        url,
    )
    if tree_match:
        owner, repo, branch, subdir = tree_match.groups()
        repo_url = f"https://github.com/{owner}/{repo}.git"
        tmp = _clone_repo(repo_url, branch)
        target = tmp / subdir
        if target.exists():
            return target, True
        # Fallback to repo root
        return tmp, True

    # GitHub repo URL (no blob/tree) → clone entire repo
    repo_match = re.match(
        r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        url,
    )
    if repo_match:
        return _clone_repo(url), True

    # Raw githubusercontent URL → fetch single file
    if "raw.githubusercontent.com" in url:
        filename = url.rstrip("/").split("/")[-1]
        return _fetch_raw_file(url, filename)

    # Generic URL → fetch as single file
    if url.endswith(".md") or url.endswith(".txt"):
        filename = url.rstrip("/").split("/")[-1]
        return _fetch_raw_file(url, filename)

    # Unknown URL format — try cloning as git repo
    try:
        return _clone_repo(url), True
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(
            f"Cannot fetch: {url}\n"
            "Supported: GitHub repos, GitHub file URLs, raw .md URLs"
        ) from e


def _fetch_raw_file(url: str, filename: str) -> tuple[Path, bool]:
    """Fetch a single file from a URL to a temp directory."""
    tmp = Path(tempfile.mkdtemp(prefix="skill-audit-"))
    # Guard against path traversal via a crafted filename in the URL.
    safe_name = Path(filename).name or "skill.md"
    dest = tmp / safe_name

    try:
        with _safe_urlopen(url, timeout=30) as resp:
            if resp.status >= 400:
                raise ValueError(f"HTTP {resp.status} fetching {url}")
            # Read one byte past the cap so we can detect an over-limit body.
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
        if len(data) > MAX_DOWNLOAD_BYTES:
            raise ValueError(
                f"Remote file exceeds {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MiB limit: {url}"
            )
        dest.write_bytes(data)
    except ValueError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    except (OSError, http.client.HTTPException) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(f"Cannot reach {url}: {e}") from e

    return dest, True


def _clone_repo(url: str, branch: str | None = None) -> Path:
    """Clone a git repo to a temp directory. Returns the repo root path.

    Hardened against git transport abuse: http(s) only (no `ext::`, `file://`,
    `ssh://`, …), option-injection blocked via `--` and leading-dash checks, and
    SSRF-validated host.
    """
    if url.startswith("-"):
        raise ValueError(f"Refusing suspicious repo URL: {url}")
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Refusing to clone non-http(s) repo: {url}")
    # Defense-in-depth: validates the host resolves public *now*. Note git
    # re-resolves the host itself at clone time, so unlike the file-fetch path
    # this cannot fully pin against DNS rebinding — the transport allowlist and
    # this check are the mitigations available without reimplementing git's I/O.
    _validate_url_safe(url)
    if branch is not None and (branch.startswith("-") or branch != branch.strip() or not branch):
        raise ValueError(f"Refusing suspicious branch name: {branch!r}")

    tmp = Path(tempfile.mkdtemp(prefix="skill-audit-"))

    cmd = [
        "git",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "protocol.http.allow=always",
        "clone",
        "--depth", "1",
    ]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.append("--")
    cmd.extend([url, str(tmp / "repo")])

    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"}

    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=60, env=env)
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(f"git clone failed: {e.stderr.decode().strip()}") from e
    except FileNotFoundError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("git not found — install git to audit remote repos") from None

    return tmp / "repo"


def cleanup_temp(path: Path) -> None:
    """Remove the skill-audit temp dir that `path` lives in.

    Only removes a directory this module created — a `mkdtemp` directory with the
    `skill-audit-` prefix that sits directly under the system temp dir. It never
    deletes by broad path prefix, so an unexpected `path` can't trigger removal of
    an unrelated directory.
    """
    tmp_root = Path(tempfile.gettempdir()).resolve()
    for candidate in [path, *path.parents]:
        if not candidate.name.startswith("skill-audit-"):
            continue
        try:
            parent_resolved = candidate.parent.resolve()
        except OSError:
            continue
        if parent_resolved == tmp_root:
            shutil.rmtree(candidate, ignore_errors=True)
            return
