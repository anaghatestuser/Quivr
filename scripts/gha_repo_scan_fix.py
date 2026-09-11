#!/usr/bin/env python3
"""Lineaje AI Policy Scanner — GitHub Actions edition.

This file is a **standalone** copy of ``gha_repo_scan.py``. The rest of
``aipo_mcp_server`` is not present on the runner — do not import
``scm_client``, ``config``, ``mcp_server``, ``adapter``, ``pipeline``,
``gha_stub_insertion``, or anything else from this repo. Stdlib only
(plus the ``mcp`` client package). If ``insertion_point_scanner.py``
happens to sit next to this file, a local stub fallback may run;
otherwise it is skipped silently.

Scans already-checked-out source code against Lineaje AI security policies
and prints results as structured JSON to stdout. Designed to run on a
GitHub-managed Ubuntu runner where the repository is pre-checked-out.

Usage::

    python scripts/gha_repo_scan.py --source-path .

Output (stdout, JSON)::

    {
      "status": "violations_found | compliant | error",
      "scan_metadata": {
        "repo": "owner/repo",
        "branch": "main",
        "head_sha": "abc1234",
        "scanned_at": "2026-05-10T10:00:00Z",
        "files_scanned": 150,
        "batches": 2,
        "failed_batches": 0
      },
      "report": "...(markdown policy report)...",
      "violations": [...],
      "aibom": [...],
      "scan_errors": []
    }

Required environment variable::

    LINEAJE_PAT_TOKEN  — Lineaje refresh token (exchanged for short-lived access tokens
                          at SCIM renew-access-token). Override with
                          LINEAJE_RENEW_ACCESS_TOKEN_URL or SCIM_SERVICE_URL.

Exit codes::

    0 — scan completed (check "status" field)
    1 — runtime error
    2 — configuration error (missing LINEAJE_PAT_TOKEN, missing repo/branch)
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import atexit
import base64
import fnmatch
import io
import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Standalone file-collection helpers (inlined from config.py)
# ===========================================================================
# This script is deployed on its own into a target repo's
# .lineaje-scanner/scripts/ by the GitHub Action — the rest of the
# aipo_mcp_server repo (including config.py) is not present there, so it
# must not import from config.py or anywhere else in this repo.
# Do not classify dependency manifests here. Pack lockfiles/toml/etc. in the
# archive; mcp_server.py routes them to CLI Integration and excludes them
# from policy scan.

EVIDENCE_TYPE_SCM_SCAN = "scm_scan"

ARCHIVE_EXCLUDE_DIRS: frozenset = frozenset(
    {
        ".git", ".gitignore", ".gitattributes", ".gitmodules", ".hg", ".svn",
        ".env", ".env.local", ".env.development", ".env.production",
        "__pycache__", ".pytest_cache", "venv", ".venv", ".venv-scan", "env", ".tox",
        "htmlcov", ".coverage", ".mypy_cache", ".ruff_cache",
        "node_modules", ".yarn", ".pnp",
        "dist", "build", ".next", ".nuxt", "out", "coverage", ".cache",
        "target", ".gradle", ".m2",
        "Pods", ".expo",
        ".idea", ".vscode",
        ".lineaje-aiepo-security",
        ".lineaje",
        "migrations", "alembic",
    }
)

ARCHIVE_EXCLUDE_GLOBS: frozenset = frozenset(
    {
        "*.secret", "*.key", "*.pem", "*.env.*",
        "*.zip", "*.tar", "*.tar.gz", "*.jar", "*.war", "*.swp", "*.swo",
        "*.min.js", "*.min.css", "*.map",
        "*_pb2.py", "*.pb.go", "*.pb.cc", "*.pb.h",
        "*.snap",
    }
)

BINARY_EXTENSIONS: frozenset = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
        ".pyc", ".pyo", ".o", ".a",
        ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
        ".db", ".sqlite", ".sqlite3",
    }
)

_ARCHIVE_EXCLUDE_DIR_GLOBS: tuple = (".venv-*", "venv-*")


def _git_ls_files_archive_command(repo_path: str) -> List[str]:
    """``git ls-files`` argv that skips the same paths the upload archive tool skips.

    ``--exclude-standard`` honors ``.gitignore``. ``-x`` drops matching *untracked*
    files. ``:(exclude,glob)`` pathspecs also drop *tracked* vendor dirs and
    binaries. Lockfiles and other dependency manifests stay in the archive;
    mcp_server.py routes them to CLI Integration and keeps them out of eval.
    """
    exclude_globs = tuple(sorted(ARCHIVE_EXCLUDE_GLOBS))
    cmd: List[str] = [
        "git", "-C", repo_path, "ls-files", "-z", "--cached", "--others", "--exclude-standard",
    ]
    x_patterns: List[str] = [
        *sorted(ARCHIVE_EXCLUDE_DIRS),
        *exclude_globs,
        *[f"*{ext}" for ext in sorted(BINARY_EXTENSIONS)],
        *_ARCHIVE_EXCLUDE_DIR_GLOBS,
    ]
    for pattern in x_patterns:
        cmd.extend(["-x", pattern])
    cmd.extend(["--", "."])
    for name in sorted(ARCHIVE_EXCLUDE_DIRS):
        cmd.append(f":(exclude,glob){name}")
        cmd.append(f":(exclude,glob){name}/**")
        cmd.append(f":(exclude,glob)**/{name}")
        cmd.append(f":(exclude,glob)**/{name}/**")
    for pat in exclude_globs:
        cmd.append(f":(exclude,glob){pat}")
        if not pat.startswith("**/"):
            cmd.append(f":(exclude,glob)**/{pat}")
    for ext in sorted(BINARY_EXTENSIONS):
        cmd.append(f":(exclude,glob)*{ext}")
        cmd.append(f":(exclude,glob)**/*{ext}")
    for pat in _ARCHIVE_EXCLUDE_DIR_GLOBS:
        cmd.append(f":(exclude,glob){pat}")
        cmd.append(f":(exclude,glob){pat}/**")
        cmd.append(f":(exclude,glob)**/{pat}")
        cmd.append(f":(exclude,glob)**/{pat}/**")
    return cmd


def _list_git_files_for_archive(repo_path: str) -> Optional[List[str]]:
    """Repo-relative files from ``_git_ls_files_archive_command``.

    Returns ``None`` if *repo_path* is not a git work tree or git cannot run.
    """
    try:
        proc = subprocess.run(
            _git_ls_files_archive_command(repo_path),
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    files: List[str] = []
    for chunk in proc.stdout.split(b"\0"):
        if not chunk:
            continue
        rel = chunk.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        if not rel:
            continue
        full = os.path.join(repo_path, rel)
        if os.path.isfile(full):
            files.append(rel)
    return files


def _walk_files_for_archive(root: str) -> List[str]:
    """``os.walk`` fallback using the same exclude sets as archive upload."""
    file_list: List[str] = []
    for dirpath, dirs, filenames in os.walk(root):
        dirs[:] = [
            d
            for d in dirs
            if d not in ARCHIVE_EXCLUDE_DIRS
            and not any(fnmatch.fnmatch(d, g) for g in _ARCHIVE_EXCLUDE_DIR_GLOBS)
        ]
        for fname in filenames:
            full_path = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(full_path, root).replace("\\", "/")
            ext = pathlib.Path(fname).suffix.lower()
            if ext in BINARY_EXTENSIONS:
                continue
            if any(part in ARCHIVE_EXCLUDE_DIRS for part in pathlib.Path(rel_path).parts):
                continue
            if any(fnmatch.fnmatch(rel_path, g) for g in ARCHIVE_EXCLUDE_GLOBS):
                continue
            file_list.append(rel_path)
    return file_list


def list_files_for_archive(repo_path: str) -> List[str]:
    """Prefer ``git ls-files`` with upload-tool excludes; walk if git is unavailable."""
    listed = _list_git_files_for_archive(repo_path)
    if listed is not None:
        return listed
    return _walk_files_for_archive(repo_path)


# Inlined from pipeline/report/consolidate.py — this script cannot import
# that module (or anything else from aipo_mcp_server) on a GHA runner.
_METRIC_HEADER_KEYS = frozenset({
    "|metric|count|",
    "|metric|value|",
    "|phase|time|",
})
_PLACEHOLDER_SNIPPETS = (
    "no policies with violations",
    "no controls enforced",
    "no skill policy violations",
    "no skill controls enforced",
    "no ai components",
    "no files scanned",
)


def _is_no_change_report(md: str) -> bool:
    text = md or ""
    return "## No Files Changed" in text or "Analysis was skipped" in text


def _norm_md_line(line: str) -> str:
    return " ".join((line or "").strip().split())


def _md_header_key(line: str) -> str:
    return "|".join(p.strip().lower() for p in _norm_md_line(line).split("|"))


def _is_separator_row(line: str) -> bool:
    s = (line or "").strip()
    if not s.startswith("|"):
        return False
    return bool(s) and all(c in "-:| " for c in s)


def _is_metric_header(header_line: str) -> bool:
    return _md_header_key(header_line) in _METRIC_HEADER_KEYS


def _is_placeholder_row(line: str) -> bool:
    low = (line or "").lower()
    return any(snippet in low for snippet in _PLACEHOLDER_SNIPPETS)


def _extract_md_tables(md: str) -> List[List[str]]:
    lines = (md or "").splitlines()
    tables: List[List[str]] = []
    i = 0
    while i < len(lines):
        if (
            lines[i].strip().startswith("|")
            and i + 1 < len(lines)
            and _is_separator_row(lines[i + 1])
        ):
            start = i
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                i += 1
            tables.append(lines[start:i])
        else:
            i += 1
    return tables


def _consolidate_batch_reports(reports: List[str]) -> str:
    """Union per-batch markdown tables into one report (stdlib-only)."""
    cleaned = [
        r.strip() for r in reports
        if (r or "").strip() and not _is_no_change_report(r)
    ]
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return cleaned[0] if cleaned[0].endswith("\n") else cleaned[0] + "\n"

    extra_rows: Dict[str, List[str]] = {}
    extra_seen: Dict[str, set] = {}
    first_keys: set = set()
    for table in _extract_md_tables(cleaned[0]):
        if table:
            first_keys.add(_md_header_key(table[0]))

    orphan_tables: List[List[str]] = []
    seen_orphan_keys: set = set()

    for report in cleaned[1:]:
        for table in _extract_md_tables(report):
            if len(table) < 2 or _is_metric_header(table[0]):
                continue
            key = _md_header_key(table[0])
            if key not in first_keys:
                if key not in seen_orphan_keys:
                    orphan_tables.append(table)
                    seen_orphan_keys.add(key)
                continue
            bucket = extra_rows.setdefault(key, [])
            seen = extra_seen.setdefault(key, set())
            for row in table[2:]:
                if _is_placeholder_row(row):
                    continue
                norm = _norm_md_line(row)
                if not norm or norm in seen:
                    continue
                seen.add(norm)
                bucket.append(row)

    lines = cleaned[0].splitlines()
    out: List[str] = []
    i = 0
    while i < len(lines):
        if (
            lines[i].strip().startswith("|")
            and i + 1 < len(lines)
            and _is_separator_row(lines[i + 1])
        ):
            header = lines[i]
            sep = lines[i + 1]
            key = _md_header_key(header)
            data_rows: List[str] = []
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                data_rows.append(lines[i])
                i += 1
            extras = extra_rows.get(key, []) if not _is_metric_header(header) else []
            if extras:
                data_rows = [r for r in data_rows if not _is_placeholder_row(r)]
            seen_local = {_norm_md_line(r) for r in data_rows}
            for row in extras:
                norm = _norm_md_line(row)
                if norm not in seen_local:
                    seen_local.add(norm)
                    data_rows.append(row)
            out.append(header)
            out.append(sep)
            out.extend(data_rows)
            continue
        out.append(lines[i])
        i += 1

    if orphan_tables:
        out.append("")
        for table in orphan_tables:
            out.extend(table)
            out.append("")

    return "\n".join(out).rstrip() + "\n"


def _combine_scan_reports(reports: List[str]) -> str:
    """Union per-batch markdown tables into one report (fallback: concatenate)."""
    nonempty = [r for r in reports if r]
    if not nonempty:
        return ""
    try:
        return _consolidate_batch_reports(nonempty)
    except Exception:
        return "\n\n---\n\n".join(nonempty)


# ===========================================================================
# Constants
# ===========================================================================

# MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"
MCP_SERVER_URL = "https://mcp.commercialdev.dev.veedna.com/mcp"

MAX_SCAN_WORKERS = 10  # keep in sync with config.py's MAX_SCAN_WORKERS (self-contained script, no import)
REMEDIATION_BRANCH_PREFIX = "remediation/unifai-gha"
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100
# GitHub rejects POST /pulls with HTTP 422 when body > 65536 chars.
GITHUB_PR_BODY_SAFE_LIMIT = 60_000
_PR_BODY_TRUNCATION_NOTE = (
    "\n\n---\n\n"
    "*…Report truncated for GitHub PR body size limit. "
    "Retrieve the full text from CI logs.*"
)

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120

# UI / GHA ``LINEAJE_PAT_TOKEN`` is a SCIM-issued refresh token. Identity-service
# ``/lineajeidentity/.../renew-access-token`` cannot decrypt it (HTTP 500
# "trying to decrypt the string"). Exchange at SCIM instead.
_SCIM_RENEW_ACCESS_TOKEN_PATH = "/scim/api/v1/auth/native/renew-access-token"
_IDENTITY_RENEW_ACCESS_TOKEN_PATH = "/lineajeidentity/api/v1/auth/native/renew-access-token"
_SCIM_SERVICE_URL_DEFAULT = "https://scim-service.commercialdev.dev.veedna.com"
_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    _SCIM_SERVICE_URL_DEFAULT + _SCIM_RENEW_ACCESS_TOKEN_PATH
)

# ===========================================================================
# Token helpers
# ===========================================================================

def _normalize_token(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip().lstrip("﻿").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _normalize_url(url: Optional[str]) -> str:
    if url is None:
        return ""
    u = str(url).strip()
    if len(u) >= 2 and u[0] == u[-1] and u[0] in "\"'":
        u = u[1:-1].strip()
    return u


def _scim_renew_url_from_identity_url(url: str) -> str:
    """Map identity-service renew URLs onto the SCIM equivalent.

    SCIM-issued refresh tokens fail at identity with HTTP 500
    ``trying to decrypt the string``.
    """
    u = (url or "").strip().rstrip("/")
    if not u or _IDENTITY_RENEW_ACCESS_TOKEN_PATH not in u:
        return u
    parsed = urllib.parse.urlparse(u)
    host = (parsed.netloc or "").replace("lineaje-identity-service", "scim-service")
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host}{_SCIM_RENEW_ACCESS_TOKEN_PATH}"


def _resolve_renew_access_token_url(explicit: Optional[str] = None) -> str:
    """SCIM renew-access-token URL for a GHA/UI refresh token.

    Order: explicit arg, LINEAJE_RENEW_ACCESS_TOKEN_URL, {SCIM_SERVICE_URL}/scim/...,
    commercialdev SCIM default. Identity-service renew URLs are rewritten to SCIM.
    """
    scim_base = _normalize_url(os.environ.get("SCIM_SERVICE_URL")).rstrip("/")
    derived = f"{scim_base}{_SCIM_RENEW_ACCESS_TOKEN_PATH}" if scim_base else ""
    raw = (
        _normalize_url(explicit)
        or _normalize_url(os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL"))
        or derived
        or _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD
    )
    rewritten = _scim_renew_url_from_identity_url(raw) or raw
    if rewritten != raw.rstrip("/"):
        logger.warning(
            "Auth: renew URL %s is identity-service; using SCIM %s "
            "(identity cannot decrypt SCIM refresh tokens)",
            raw, rewritten,
        )
    return rewritten.rstrip("/")


def _identity_token_response_dict(raw_text: str, *, context: str) -> dict:
    text = raw_text.strip() if raw_text else ""
    try:
        parsed: Any = json.loads(raw_text)
    except json.JSONDecodeError:
        # Some endpoints return a bare JWT string
        parts = text.split(".")
        if context == "renew-access-token" and len(parts) == 3:
            return {"access_token": text}
        raise RuntimeError(f"{context}: response is not valid JSON") from None
    for _ in range(8):
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, str):
            s = parsed.strip()
            if not s:
                raise RuntimeError(f"{context}: empty JSON string where object expected")
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                parts = s.split(".")
                if context == "renew-access-token" and len(parts) == 3:
                    return {"access_token": s}
                raise RuntimeError(f"{context}: server returned error string: {s[:800]}") from None
            continue
        break
    raise RuntimeError(f"{context}: unexpected JSON type after unwrap: {type(parsed).__name__}")


class RefreshTokenTokenManager:
    """Exchange LINEAJE_PAT_TOKEN (a refresh token) for short-lived MCP bearer tokens,
    auto-renewing before expiry."""

    def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
        self._refresh_token = _normalize_token(refresh_token)
        if not self._refresh_token:
            raise ValueError("LINEAJE_PAT_TOKEN must be non-empty")
        self._renew_url = _resolve_renew_access_token_url(renew_access_token_url)
        self._lock = threading.Lock()
        self._access_token = ""
        self._access_deadline = 0.0
        try:
            self._skew_sec = int(os.environ.get(
                "LINEAJE_TOKEN_REFRESH_SKEW_SEC", str(_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC)
            ))
        except ValueError:
            self._skew_sec = _DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC

    def get_access_token(self) -> str:
        with self._lock:
            return self._get_unlocked()

    def _get_unlocked(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_deadline - self._skew_sec:
            return self._access_token
        self._renew()
        if not self._access_token:
            raise RuntimeError("renew-access-token did not return access_token")
        return self._access_token

    def _renew(self) -> None:
        q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
        url = f"{self._renew_url}?{q}"
        req = urllib.request.Request(
            url, data=b"null",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = _identity_token_response_dict(resp.read().decode(), context="renew-access-token")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"renew-access-token HTTP {exc.code}: {body[:800]}") from exc
        at = (data.get("access_token") or "").strip()
        if not at:
            raise RuntimeError(f"Token response missing access_token: {data!r}")
        self._access_token = at
        rt = (data.get("refresh_token") or "").strip()
        if rt:
            self._refresh_token = rt
        exp = data.get("expires_in")
        try:
            exp_sec = int(exp) if exp is not None else 3600
        except (TypeError, ValueError):
            exp_sec = 3600
        self._access_deadline = time.time() + max(60, exp_sec)
        logger.debug("Access token renewed; expires in %ds", exp_sec)


def _looks_like_jwt_blob(value: str) -> bool:
    s = value.strip()
    if s.count(".") != 2:
        return False
    hdr, payload, sig = s.split(".")
    if len(hdr) < 10 or len(payload) < 10 or len(sig) < 10:
        return False
    seg = re.compile(r"^[A-Za-z0-9_-]+$")
    return bool(seg.match(hdr) and seg.match(payload) and seg.match(sig))


def _looks_like_already_usable_bearer(value: str) -> bool:
    """True if *value* is already a Bearer (JWT). Opaque refresh tokens and PATs
    are exchanged via renew-access-token, not sent as Bearer / introspected.
    """
    s = value.strip()
    if not s:
        return False
    return _looks_like_jwt_blob(s)


def _scan_refresh_token(args: Optional[argparse.Namespace] = None) -> str:
    """PAT / refresh token from ``--lineaje-pat`` / ``--refresh-token`` or GHA env.

    Never hardcoded. Customer stubs store this as ``refreshtoken`` and exchange
    it for a Bearer.
    """
    cli = ""
    if args is not None:
        cli = _normalize_token(
            getattr(args, "lineaje_pat", None) or getattr(args, "refresh_token", None)
        )
    return cli or _normalize_token(
        os.environ.get("LINEAJE_PAT_TOKEN", "")
        or os.environ.get("LINEAJE_REFRESH_TOKEN", "")
    )


def build_bearer_getter(refresh_token: str = "") -> Callable[[], str]:
    """Return a callable that yields the MCP bearer, from LINEAJE_PAT_TOKEN.

    LINEAJE_PAT_TOKEN holds one of two different things depending on how it was minted:
    - A native **refresh token** (opaque, standard-Base64 string) — exchanged via
      renew-access-token to obtain a short-lived access token before use.
    - An already-short-lived **access token** (JWT, or any base64url-shaped token) —
      usable directly. Sending one of these to renew-access-token's ``refreshToken``
      param fails server-side ("Illegal base64 character 5f" etc.), since the identity
      service tries to base64-decode it with the *standard* alphabet and chokes on
      base64url's ``-``/``_`` or JWTs' internal ``.`` separators.
    """
    pat = _normalize_token(refresh_token or os.environ.get("LINEAJE_PAT_TOKEN", ""))
    if not pat:
        raise RuntimeError("LINEAJE_PAT_TOKEN / --lineaje-pat is not set")
    if _looks_like_already_usable_bearer(pat):
        logger.info("LINEAJE_PAT_TOKEN is already a usable access token — using directly as bearer")
        return lambda: pat
    mgr = RefreshTokenTokenManager(pat)
    return mgr.get_access_token

# ===========================================================================
# HEAD SHA resolution
# ===========================================================================

def _resolve_head_sha_from_source(source_path: str) -> str:
    """Best-effort fallback: read HEAD's commit SHA straight from the git repo
    at *source_path* when neither ``--head-sha`` nor ``$GITHUB_SHA`` was given.

    Mirrors ``repo_scan.py``'s ``resolve_head_sha`` — since ``--source-path``
    is already a checked-out git repo, there's no need to ask the caller for
    a value git already knows. Returns "" (not raised) on any failure, so
    the normal "missing config" error still fires with a clear message.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_path, capture_output=True, text=True, timeout=10, check=True,
        )
        sha = result.stdout.strip()
        if sha:
            logger.info(
                "head_sha not provided — resolved from git HEAD at %s: %s",
                source_path, sha[:7],
            )
        return sha
    except Exception as exc:
        logger.debug("Could not resolve HEAD SHA from %s: %s", source_path, exc)
        return ""


# ===========================================================================
# Self-clone (--clone)
# ===========================================================================

def clone_repository(
    repo_slug: str,
    branch: str,
    clone_dir: str,
    scm_token: str,
    timeout: int = 300,
    max_retries: int = 2,
) -> None:
    """Clone *repo_slug* (``owner/repo``) at *branch* into *clone_dir*.

    Opt-in via ``--clone`` — this script normally assumes ``--source-path`` is
    already a checkout (its original GHA-runner design: ``actions/checkout``
    runs first). ``--clone`` lets it fetch the code itself instead, using an
    ``x-access-token``-authenticated HTTPS URL, same auth pattern already
    proven in ``veracode_repo_scan.py``'s ``clone_repository``.
    """
    auth_url = f"https://x-access-token:{scm_token}@github.com/{repo_slug}.git"
    logger.info("Cloning %s (branch=%s) ...", repo_slug, branch)
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--branch", branch, auth_url, clone_dir]
    last_exc: Exception = RuntimeError("Clone did not run")
    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            logger.warning("Retrying clone (attempt %d/%d) ...", attempt, max_retries)
            shutil.rmtree(clone_dir, ignore_errors=True)
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
            logger.info("Clone successful: %s", clone_dir)
            return
        except subprocess.TimeoutExpired as exc:
            logger.error("Clone timed out after %ds (attempt %d/%d)", timeout, attempt, max_retries)
            last_exc = exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").replace(scm_token, "***")
            logger.error("Clone failed for %s: %s", repo_slug, stderr[:300])
            raise
    raise last_exc


# ===========================================================================
# File collection
# ===========================================================================

def collect_repo_files(local_path: str) -> List[str]:
    """List scannable files via ``git ls-files``; excludes live in the upload tool."""
    return list_files_for_archive(local_path)

# ===========================================================================
# Archive creation
# ===========================================================================

def _norm_archive_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def create_batch_archive(
    source_dir: str,
    archive_dir: str,
    file_subset: List[str],
    source_code_repo: str,
    branch: str,
    head_sha: str,
    batch_index: int = 0,
    run_id: str = "",
    manifest_files: Optional[List[str]] = None,
) -> str:
    archive_path = os.path.join(archive_dir, f"repo_scan_batch_{batch_index}.tar.gz")
    extra_manifests = [m for m in (manifest_files or []) if m not in file_subset]
    all_files = list(file_subset) + extra_manifests
    with tarfile.open(archive_path, "w:gz") as tf:
        for rel_path in all_files:
            full_path = os.path.join(source_dir, rel_path)
            if os.path.isfile(full_path):
                tf.add(full_path, arcname=rel_path, recursive=False)
        metadata = {
            "scan_source": "gha_repo_scan",
            "repo": source_code_repo,
            "branch": branch,
            "head_sha": head_sha,
            "scan_type": "full_repository",
            "evidence_type": EVIDENCE_TYPE_SCM_SCAN,
            "batch_index": batch_index,
            "batch_file_count": len(file_subset),
            "manifest_file_count": len(extra_manifests),
        }
        metadata_bytes = json.dumps(metadata, indent=2).encode("utf-8")
        metadata_info = tarfile.TarInfo(name="user_metadata.json")
        metadata_info.size = len(metadata_bytes)
        tf.addfile(metadata_info, io.BytesIO(metadata_bytes))
    size_kb = os.path.getsize(archive_path) // 1024
    logger.info(
        "Batch archive #%d: %d files + %d manifests, %d KB",
        batch_index, len(file_subset), len(extra_manifests), size_kb,
    )
    return archive_path


def _build_batch_file_contents(
    source_dir: str,
    file_subset: List[str],
    source_code_repo: str,
    branch: str,
    head_sha: str,
    batch_index: int = 0,
    manifest_files: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Read a batch's files (+ manifests) as text for get_upload_url's `files`
    param — no local .tar.gz needed for the upload itself (mcp_server.py
    builds the tarball server-side from this dict). Mirrors
    create_batch_archive's file selection and embedded user_metadata.json
    exactly, just built as an in-memory dict instead of written to disk.
    """
    extra_manifests = [m for m in (manifest_files or []) if m not in file_subset]
    all_files = list(file_subset) + extra_manifests
    contents: Dict[str, str] = {}
    for rel_path in all_files:
        full_path = os.path.join(source_dir, rel_path)
        if os.path.isfile(full_path):
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                contents[rel_path] = f.read()
    metadata = {
        "scan_source": "gha_repo_scan",
        "repo": source_code_repo,
        "branch": branch,
        "head_sha": head_sha,
        "scan_type": "full_repository",
        "evidence_type": EVIDENCE_TYPE_SCM_SCAN,
        "batch_index": batch_index,
        "batch_file_count": len(file_subset),
        "manifest_file_count": len(extra_manifests),
    }
    contents["user_metadata.json"] = json.dumps(metadata, indent=2)
    logger.info(
        "Batch files payload #%d: %d files + %d manifests",
        batch_index, len(file_subset), len(extra_manifests),
    )
    return contents


def _is_payload_too_large(exc: BaseException) -> bool:
    """True when exc is (or wraps) an HTTP 413 from the MCP endpoint.

    A 413 means a proxy/gateway in front of the MCP server rejected the
    request body itself — get_upload_url's own files-size guard never even
    ran. Unlike a transient network blip, retrying the identical payload is
    guaranteed to 413 again; the caller should split the batch instead of
    (or before) any blind retry.
    """
    cause = exc
    while hasattr(cause, "exceptions") and cause.exceptions:
        cause = cause.exceptions[0]
    try:
        import httpx
        if isinstance(cause, httpx.HTTPStatusError) and cause.response is not None:
            return cause.response.status_code == 413
    except Exception:
        pass
    # Fallback for a transport/wrapper that doesn't preserve the exception
    # type (e.g. re-raised as a bare RuntimeError with the original message
    # baked in) — this exact phrase is distinctive enough not to false-match.
    text = str(cause)
    return "413" in text and "Request Entity Too Large" in text


def _batch_size(total_files: int) -> int:
    raw = (os.environ.get("UNIFAI_FILE_BATCH_SIZE") or "").strip()
    if not raw:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    try:
        size = int(raw)
    except ValueError:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    if size <= 0:
        return max(1, total_files)
    return size

# ===========================================================================
# MCP scan (SDK path only)
# ===========================================================================

def _upload_to_s3(presigned_url: str, archive_path: str) -> None:
    size = os.path.getsize(archive_path)
    logger.info("Uploading %d KB to S3 ...", size // 1024)
    with open(archive_path, "rb") as f:
        req = urllib.request.Request(
            presigned_url, data=f.read(), method="PUT",
            headers={"Content-Type": "application/gzip" if archive_path.endswith((".tar.gz", ".tgz")) else "application/zip"},
        )
        with urllib.request.urlopen(req) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"S3 upload failed: HTTP {resp.status}")
    logger.info("S3 upload complete")


def _loads_scan_payload(raw: str) -> dict:
    """Parse plain JSON or report-first MCP scan text (stdlib only)."""
    text = (raw or "").strip()
    if not text:
        return {"raw": "empty response"}
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    marker = "<!-- LINEAJE_MCP_JSON -->"
    if marker in text:
        json_part = text.split(marker, 1)[1].strip()
        try:
            parsed = json.loads(json_part)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    brace = text.rfind("\n{")
    if brace >= 0:
        try:
            parsed = json.loads(text[brace + 1 :])
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    return {"raw": text, "report": text}


def _parse_tool_result(result: Any) -> dict:
    for attr in ("structuredContent", "structured_content"):
        structured = getattr(result, attr, None)
        if isinstance(structured, dict) and (
            "report" in structured or "status" in structured or "error" in structured
        ):
            return structured
    if hasattr(result, "content") and result.content:
        raw = result.content[0].text if hasattr(result.content[0], "text") else str(result.content[0])
        return _loads_scan_payload(raw)
    return {"raw": "empty response"}


# --- mcp SDK compat shim ----------------------------------------------------
# ``streamablehttp_client`` (this exact name) was a deprecated alias for the
# canonical ``streamable_http_client`` in the ``mcp`` PyPI package. Some ``mcp``
# releases have removed the deprecated alias outright, which breaks on any
# environment that installs ``mcp`` unpinned (e.g. a CI runner picking up
# whatever's newest — confirmed live: "ImportError: cannot import name
# 'streamablehttp_client' from 'mcp.client.streamable_http'"). Reimplemented
# here against the still-supported ``streamable_http_client`` so every call
# site below keeps working unchanged regardless of which alias the installed
# mcp version kept. Logic mirrors the (now possibly-removed) deprecated
# wrapper's own implementation exactly — same signature, same behavior.
from contextlib import asynccontextmanager as _asynccontextmanager
from datetime import timedelta as _timedelta


@_asynccontextmanager
async def streamablehttp_client(
    url,
    headers=None,
    timeout=30,
    sse_read_timeout=60 * 5,
    terminate_on_close=True,
    httpx_client_factory=None,
    auth=None,
):
    import httpx
    from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

    factory = httpx_client_factory or create_mcp_http_client
    timeout_seconds = timeout.total_seconds() if isinstance(timeout, _timedelta) else timeout
    sse_read_timeout_seconds = (
        sse_read_timeout.total_seconds() if isinstance(sse_read_timeout, _timedelta) else sse_read_timeout
    )
    client = factory(
        headers=headers,
        timeout=httpx.Timeout(timeout_seconds, read=sse_read_timeout_seconds),
        auth=auth,
    )
    async with client:
        async with streamable_http_client(
            url, http_client=client, terminate_on_close=terminate_on_close,
        ) as streams:
            yield streams


def _run_mcp_scan_via_client(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
    head_sha: str = "",
    is_last_batch: bool = True,
) -> Dict[str, Any]:
    from mcp import ClientSession

    async def _scan() -> Dict[str, Any]:
        base_args: Dict[str, Any] = {
            "source_code_repo": source_code_repo,
            "branch_or_tag": branch,
            "files_to_scan": files_to_scan,
        }
        # CI/scripts path (get_upload_url's own docstring): call it with NONE
        # of local_archive_path/archive_content_base64/files, and it returns a
        # bare presigned_url without uploading anything itself. We then PUT
        # the already-built batch archive straight to S3 ourselves. Unlike
        # `files={...}` (every file's content embedded in THIS request's own
        # JSON body, routed through the MCP endpoint), this PUT goes directly
        # to S3 — it never passes through whatever proxy/gateway sits in
        # front of the MCP endpoint, so it isn't subject to that transport's
        # request-body-size limit. `files={...}` could 413 there even after
        # splitting a batch down to a single oversized file — a floor no
        # amount of client-side re-batching can get under.
        upload_args: Dict[str, Any] = dict(base_args)
        # Only known to the SCM/CI script — a coding agent (Cursor/Claude Code) has no
        # way to set a custom transport header, so this signal cannot leak into IDE scans.
        scm_headers: Dict[str, str] = {"X-Unifai-Commit-Sha": head_sha} if head_sha else {}

        tok1 = bearer_getter()
        async with streamablehttp_client(
            server_url, headers={"Authorization": f"Bearer {tok1}", **scm_headers},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                logger.info("MCP step 1/3: get_upload_url")
                upload_result = _parse_tool_result(
                    await session.call_tool("get_upload_url", arguments=upload_args)
                )
                if not upload_result.get("success"):
                    raise RuntimeError(f"get_upload_url failed: {upload_result.get('error', upload_result)}")
                archive_id = upload_result["archive_id"]
                presigned_url = upload_result.get("presigned_url")

        # Calling get_upload_url with no files/local_archive_path/base64
        # always returns a bare presigned_url and never uploads anything
        # itself (see its docstring's CI/scripts branch). Missing one here
        # means the server's contract changed underneath us.
        if not presigned_url:
            raise RuntimeError(
                "get_upload_url did not return presigned_url for a files-less "
                f"request — unexpected server response: {upload_result!r}"
            )
        logger.info("MCP step 2/3: uploading batch archive to S3 directly")
        _upload_to_s3(presigned_url, archive_path)

        tok2 = bearer_getter()
        sse_timeout = int(os.environ.get("UNIFAI_MCP_SSE_READ_TIMEOUT", "1800"))
        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok2}", **scm_headers},
            sse_read_timeout=sse_timeout,
        ) as (read2, write2, _):
            async with ClientSession(read2, write2) as session2:
                await session2.initialize()
                logger.info("MCP step 3/3: analyze_uploaded_archive (timeout=%ds)", sse_timeout)
                analyze_args = dict(base_args)
                analyze_args["archive_id"] = archive_id
                # We already know the exact URL we used to reach this server -- more
                # reliable than any guess the server itself could make about its own
                # public address. Every other caller of this tool leaves this "" (the
                # server-side default) and gets the server's own resolution instead.
                analyze_args["mcp_server_location"] = server_url
                analyze_args["scan_type"] = EVIDENCE_TYPE_SCM_SCAN
                analyze_args["is_last_batch"] = is_last_batch
                result = _parse_tool_result(
                    await session2.call_tool("analyze_uploaded_archive", arguments=analyze_args)
                )
                return result

    return asyncio.run(_scan())


def run_mcp_scan(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
    head_sha: str = "",
    is_last_batch: bool = True,
) -> Dict[str, Any]:
    """is_last_batch=False buffers this batch's entities/findings server-side
    instead of uploading (see uploader.py's upload_pipeline_results_batched) —
    pass it for every call of a multi-batch scan except the final one, so the
    whole scan produces exactly one entities PUT and one findings PUT instead
    of one pair per batch. Default True matches a single-batch scan's
    existing immediate-upload behavior.

    archive_path (from create_batch_archive) is PUT directly to S3 via a
    presigned URL from get_upload_url's CI/scripts (files-less) branch —
    chosen over `files={...}` specifically because the PUT bypasses the MCP
    endpoint's own request-body-size limit (a plain S3 PUT has no comparable
    ceiling), where inline file content embedded in the tool-call body does
    not."""
    logger.info("MCP scan: %d files, repo=%s, branch=%s", len(files_to_scan), source_code_repo, branch)
    return _run_mcp_scan_via_client(
        server_url, bearer_getter, source_code_repo, branch, files_to_scan, archive_path,
        head_sha=head_sha, is_last_batch=is_last_batch,
    )

# ===========================================================================
# Guardrail stub insertion (standalone — no sibling-file / repo dependency)
# ===========================================================================
#
# analyze_uploaded_archive already computes "stub_insertions" server-side
# (adapter.py's _scan_stub_insertions_readonly, same insertion_point_scanner.py
# logic the MCP server itself uses) and returns it in each batch's JSON
# response — file, line, proposed_stub (the exact code to insert),
# import_needed (the gr_check()-family helper for that language, inlined once
# per file), safe_to_insert, skip_reason, insert_after. Applying it here needs
# nothing beyond that JSON + stdlib: no gha_stub_insertion.py, no checkout of
# the aipo_mcp_server pipeline alongside this script. That older path
# (gha_stub_insertion.py) additionally re-derived stubs locally via
# pipeline/stub/guardrail_stub_insertion.py — a much heavier, SiteDescriptor/
# companion-module design requiring this repo's full pipeline package on the
# runner, which a truly standalone script (this one, meant to be the only
# Lineaje file a customer's workflow needs) can't assume.

# Per-language marker proving the shared gr_check()-family helper this
# extension's import_needed text defines is already present in a file — skip
# re-inserting it (harmless duplicate `def`/`function` in Python/JS, but a
# real SyntaxError for a duplicate top-level `class`/`func` in Java/Go).
_GR_CHECK_MARKERS: Dict[str, str] = {
    ".py": "def gr_check(",
    ".js": "function gr_check(",
    ".jsx": "function gr_check(",
    ".ts": "function gr_check(",
    ".tsx": "function gr_check(",
    ".go": "func grCheck(",
    ".java": "class GrClient {",
}


def _module_prefix_insert_index(lines: List[str]) -> int:
    """0-indexed position to insert a new top-level block at — after any
    shebang/encoding comment AND after a leading module docstring, if
    present. Only the first statement in a Python file is its module
    docstring; inserting above it silently demotes it to a dead string-
    literal expression. Falls back to shebang/encoding-only detection for
    non-Python sources — never raises."""
    idx = 0
    for i, ln in enumerate(lines[:5]):
        if ln.startswith("#!") or ln.strip().startswith("# -*-"):
            idx = i + 1
        if ln.startswith("package "):
            idx = max(idx, i + 1)
    try:
        tree = ast.parse("".join(lines))
        first = tree.body[0] if tree.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(getattr(first, "value", None), ast.Constant)
            and isinstance(first.value.value, str)
        ):
            idx = max(idx, first.end_lineno)
    except SyntaxError:
        pass
    return idx


def safe_prefix_insert_index(lines: List[str]) -> int:
    """Like _module_prefix_insert_index(), but also walks past any leading
    `from __future__ import` line(s) — those must be the first statement(s)
    in a Python file; inserting anything above one is a real SyntaxError."""
    insert_at = _module_prefix_insert_index(lines)
    while insert_at < len(lines) and lines[insert_at].lstrip().startswith("from __future__ import"):
        insert_at += 1
    return insert_at


def validate_python_source(new_content: str, abs_path: str) -> Optional[str]:
    """Whole-file compile() check after a stub insertion. Returns None if
    still valid, else the SyntaxError message. compile(), not ast.parse() —
    ast.parse() does not enforce future-import placement."""
    try:
        compile(new_content, abs_path, "exec")
        return None
    except SyntaxError as exc:
        return str(exc)


def _norm_stub_relpath(path: str) -> str:
    """Repo-relative path used only for stub-identity comparison."""
    p = (path or "").replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    if os.path.basename(p) == "gr_stub_client.py":
        return "gr_stub_client.py"
    return p


def _stub_identity_keys(row: Dict[str, Any]) -> list:
    rel = _norm_stub_relpath(str(row.get("file") or ""))
    try:
        line = int(row.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    ip = str(row.get("insertion_point") or "")
    site = str(row.get("site_id") or "")
    keys: list = []
    if site:
        keys.append(("site", site))
    if rel:
        keys.append(("loc", rel, line, ip))
        if line == 0 and not ip:
            keys.append(("file", rel))
    return keys


def _dedupe_stub_insertions(stubs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse overlapping batches / path aliases into one row per site."""
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for s in stubs:
        if not isinstance(s, dict):
            out.append(s)
            continue
        entry = dict(s)
        rel = _norm_stub_relpath(str(s.get("file") or ""))
        if rel:
            entry["file"] = rel
        keys = _stub_identity_keys(entry)
        if keys and any(k in seen for k in keys):
            if entry.get("new_content"):
                for i, kept in enumerate(out):
                    if not isinstance(kept, dict):
                        continue
                    kept_keys = _stub_identity_keys(kept)
                    if any(k in kept_keys for k in keys):
                        merged = dict(kept)
                        merged["new_content"] = entry["new_content"]
                        merged["status"] = "detected"
                        merged["safe_to_insert"] = True
                        merged["file"] = rel or merged.get("file") or ""
                        out[i] = merged
                        break
            continue
        for k in keys:
            seen.add(k)
        out.append(entry)
    return out


def _collapse_stub_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen_sites: set = set()
    seen_loc: set = set()
    out: List[Dict[str, Any]] = []
    for hit in sorted(hits, key=lambda h: int(h.get("line") or 0)):
        site = str(hit.get("site_id") or "")
        try:
            line = int(hit.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        loc = (line, str(hit.get("insertion_point") or ""))
        if site and site in seen_sites:
            continue
        if loc in seen_loc:
            continue
        if site:
            seen_sites.add(site)
        seen_loc.add(loc)
        out.append(hit)
    return out


def _stub_insertions_from_mcp_result(mcp_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Merge stub_insertions with patched_files / companion_files from the MCP response."""
    stubs = [dict(s) for s in (mcp_result.get("stub_insertions") or [])]
    by_file: Dict[str, str] = {}
    for extra in list(mcp_result.get("patched_files") or []) + list(mcp_result.get("companion_files") or []):
        if not isinstance(extra, dict):
            continue
        rel = _norm_stub_relpath(extra.get("file") or "")
        if rel and extra.get("content") is not None:
            by_file[rel] = extra["content"]
    if not by_file:
        return _dedupe_stub_insertions(stubs)
    applied: set = set()
    for s in stubs:
        rel = _norm_stub_relpath(s.get("file") or "")
        if rel:
            s["file"] = rel
        if rel in by_file:
            s["new_content"] = by_file[rel]
            s["status"] = "detected"
            s["safe_to_insert"] = True
            applied.add(rel)
    for rel, content in by_file.items():
        if rel not in applied:
            stubs.append({
                "file": rel,
                "status": "detected",
                "safe_to_insert": True,
                "new_content": content,
                "line": 0,
            })
    return _dedupe_stub_insertions(stubs)


def apply_stub_insertions_to_clone(
    stub_insertions: List[Dict[str, Any]],
    source_dir: str,
) -> Tuple[Dict[str, str], List[str]]:
    """Apply the server-computed stub_insertions to files under source_dir.

    Returns ``(validated_fixes, failed_or_skipped)`` — validated_fixes maps
    repo-relative path -> new file content, ready for _create_fix_pr.
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    skipped: List[str] = []
    validated: Dict[str, str] = {}
    for s in _dedupe_stub_insertions(stub_insertions):
        rel = _norm_stub_relpath(s.get("file") or "")
        if not rel:
            continue
        if s.get("status") != "detected":
            continue  # "already_present" — nothing to do
        if s.get("new_content"):
            # Server already instrumented the extracted archive — write the
            # whole file rather than re-applying proposed_stub line-by-line.
            validated[rel] = s["new_content"]
            continue
        if rel in validated:
            continue
        if not s.get("safe_to_insert"):
            skipped.append(f"{rel}:{s.get('line', '')} {s.get('skip_reason', '') or 'unsafe'}".strip())
            continue
        by_file.setdefault(rel, []).append(s)

    for rel_path, hits in by_file.items():
        if rel_path in validated:
            continue
        abs_path = os.path.join(source_dir, rel_path)
        if not os.path.isfile(abs_path):
            skipped.append(f"{rel_path} not found in checkout")
            continue

        with open(abs_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        ext = pathlib.Path(rel_path).suffix.lower()

        # Insert bottom-up so an earlier insertion never shifts a later hit's
        # (already-captured) line number out from under it.
        sorted_hits = sorted(_collapse_stub_hits(hits), key=lambda h: h.get("line", 0), reverse=True)
        needs_import = False
        for hit in sorted_hits:
            proposed = hit.get("proposed_stub") or ""
            if not proposed:
                continue
            site = str(hit.get("site_id") or "")
            joined = "".join(lines)
            marker = f"site_id={site!r}" if site else ""
            if (marker and marker in joined) or proposed in joined:
                continue
            line = int(hit.get("line") or 0)
            # 1-based line; insert_after=True (result/lhs patterns) must land
            # AFTER the line assigning the variable the stub references —
            # inserting before it is a NameError.
            idx = max(0, line if hit.get("insert_after") else line - 1)
            idx = min(idx, len(lines))
            lines.insert(idx, proposed + "\n")
            needs_import = True

        if needs_import:
            import_block = next(
                (h.get("import_needed") for h in hits if h.get("import_needed")), "",
            )
            marker = _GR_CHECK_MARKERS.get(ext, "def gr_check(")
            if import_block and marker not in "".join(lines):
                lines.insert(safe_prefix_insert_index(lines), import_block.rstrip("\n") + "\n")

        new_content = "".join(lines)
        if ext == ".py":
            syntax_err = validate_python_source(new_content, abs_path)
            if syntax_err:
                skipped.append(f"{rel_path} would be invalid Python after insertion ({syntax_err})")
                continue

        validated[rel_path] = new_content

    logger.info("Stub insertions applied: %d file(s) changed", len(validated))
    return validated, skipped


_GUARDRAIL_MANIFEST_REL = ".lineaje/guardrail.json"
_HARDCODED_GR_ORIGIN = "https://mcp.commercialdev.dev.veedna.com"


def _usable_scan_refresh_token(raw: str) -> str:
    """SCIM refresh token only — never a JWT, URL, or identity ``lineaje_pat_``."""
    s = _normalize_token(raw)
    if not s or s.startswith("http"):
        return ""
    if s.count(".") == 2 and s.startswith("eyJ"):
        return ""
    if s.startswith("lineaje_pat"):
        return ""
    return s


def _ensure_refresh_token_in_validated_fixes(
    validated_fixes: Dict[str, str],
    refresh_token: str,
    source_dir: str = "",
) -> None:
    """Write the GHA SCIM refresh token into customer ``guardrail.json``.

    MCP often has only the access JWT (already exchanged) and cannot store a
    usable ``refreshtoken``. Identity PATs are not stored — runtime stubs
    exchange this token at SCIM renew-access-token.
    """
    rel = _GUARDRAIL_MANIFEST_REL
    rt = _usable_scan_refresh_token(refresh_token)
    try:
        data = json.loads(validated_fixes.get(rel, "") or "{}")
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    existing = str(data.get("refreshtoken") or data.get("refresh_token") or "").strip()
    keep = _usable_scan_refresh_token(existing)
    token = keep or rt
    if not token:
        logger.warning(
            "No SCIM refresh token for %s — set --lineaje-pat / LINEAJE_PAT_TOKEN "
            "(do not store a JWT or lineaje_pat_ identity PAT)",
            rel,
        )
        return
    data.setdefault("contract_version", "2.0")
    base = str(data.get("gr_service_url") or "").strip().rstrip("/") or _HARDCODED_GR_ORIGIN
    data["gr_service_url"] = base
    data["enforce_endpoint"] = f"{base}/enforce"
    data["refreshtoken"] = token
    data.pop("refresh_token", None)
    data.setdefault("generated_by", "gha_repo_scan")
    data["note"] = (
        "Runtime guardrail stubs read refreshtoken from this file, exchange it "
        "at SCIM renew-access-token for a short-lived Bearer, and POST /enforce. "
        "Env GR_SERVICE_URL / LINEAJE_REFRESH_TOKEN / LINEAJE_PAT_TOKEN override "
        "the manifest when set."
    )
    updated = json.dumps(data, indent=2) + "\n"
    validated_fixes[rel] = updated
    if source_dir:
        dest = os.path.join(source_dir, rel)
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(updated)
        except OSError as exc:
            logger.warning("Could not write %s: %s", dest, exc)
    logger.info("Customer %s refreshtoken=set (SCIM refresh token)", rel)


# Extensions insertion_point_scanner.scan_file() actually scans. Passing the
# full GHA file_list (lockfiles, markdown, images) is a no-op per file but
# wastes runner time; restrict to these.
_LOCAL_STUB_SCANNABLE_EXTS = frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"})
_LOCAL_STUB_SKIP_BASENAMES = frozenset({
    "gr_stub_client.py",
    "gha_repo_scan.py",
    "gha_repo_scan_fix.py",
    "gha_stub_insertion.py",
    "lineaje_ai_scan.py",
    "insertion_point_scanner.py",
    "scan_common.py",
})
_LOCAL_STUB_MAX_FILES = 200


def _sibling_insertion_point_scanner_path() -> str:
    """Path of a co-deployed scanner sitting next to this script, if any."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "insertion_point_scanner.py")


def _ensure_insertion_point_scanner_on_path() -> bool:
    """Return True only when ``insertion_point_scanner.py`` is next to this file.

    Never adds the aipo_mcp_server repo root (or any other parent) to
    ``sys.path`` — this script must stay standalone on a GHA runner that
    ships only ``gha_repo_scan.py``.
    """
    scanner = _sibling_insertion_point_scanner_path()
    if not os.path.isfile(scanner):
        return False
    here = os.path.dirname(scanner)
    if here not in sys.path:
        sys.path.insert(0, here)
    return True


def _rel_candidate_file(file_path: str, source_dir: str) -> str:
    path = (file_path or "").strip().replace("\\", "/")
    if not path:
        return ""
    src = os.path.realpath(source_dir)
    abs_path = path if os.path.isabs(path) else os.path.normpath(os.path.join(src, path))
    try:
        rel = os.path.relpath(os.path.realpath(abs_path), src)
    except ValueError:
        return os.path.basename(path).replace("\\", "/")
    if rel.startswith(".."):
        return os.path.basename(path).replace("\\", "/")
    return rel.replace("\\", "/")


def _scannable_files_for_local_stubs(
    violations: List[Dict[str, Any]],
    file_list: List[str],
    source_dir: str,
) -> List[str]:
    """Prefer files named in violations; otherwise every scannable path in file_list."""
    listed = {(f or "").replace("\\", "/") for f in file_list}
    from_violations: List[str] = []
    seen: set = set()
    for v in violations or []:
        rel = _rel_candidate_file(v.get("file") or "", source_dir)
        if (
            rel
            and rel in listed
            and pathlib.Path(rel).suffix.lower() in _LOCAL_STUB_SCANNABLE_EXTS
            and pathlib.Path(rel).name.lower() not in _LOCAL_STUB_SKIP_BASENAMES
            and rel not in seen
        ):
            seen.add(rel)
            from_violations.append(rel)
    if from_violations:
        return from_violations
    return [
        f.replace("\\", "/")
        for f in file_list
        if pathlib.Path(f).suffix.lower() in _LOCAL_STUB_SCANNABLE_EXTS
        and pathlib.Path(f).name.lower() not in _LOCAL_STUB_SKIP_BASENAMES
    ]


def local_stub_insertions_from_checkout(
    source_dir: str,
    file_list: List[str],
    violations: List[Dict[str, Any]],
    *,
    lineaje_pat: str = "",
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Scan the GHA checkout with insertion_point_scanner and apply stubs.

    Replaces the old ``gha_stub_insertion`` import, which required this
    repo's full ``pipeline/stub`` package — never present on a customer
    runner. Returns the same ``(validated_fixes, failed, fix_table)`` shape
    ``_execute_scan`` uses for the MCP-provided stub_insertions path.
    """
    if not _ensure_insertion_point_scanner_on_path():
        raise ModuleNotFoundError(
            "insertion_point_scanner.py is not co-deployed next to this script"
        )
    from insertion_point_scanner import scan_project as _scan_project_local
    from insertion_point_scanner import _import_hint as _local_import_hint

    targets = _scannable_files_for_local_stubs(violations, file_list, source_dir)
    if not targets:
        logger.info("Local insertion-point scan: no scannable files in checkout")
        return {}, [], []
    if len(targets) > _LOCAL_STUB_MAX_FILES:
        logger.warning(
            "Local insertion-point scan: capping %d scannable file(s) to %d",
            len(targets), _LOCAL_STUB_MAX_FILES,
        )
        targets = targets[:_LOCAL_STUB_MAX_FILES]

    candidates, _mw = _scan_project_local(
        project_root=source_dir,
        files_to_scan=targets,
        lineaje_pat=lineaje_pat or "",
        max_files=max(len(targets), 1),
    )
    stub_insertions: List[Dict[str, Any]] = []
    for c in candidates:
        rel = _rel_candidate_file(c.file, source_dir)
        stub_insertions.append({
            "file": rel,
            "line": c.line,
            "status": "detected",
            "proposed_stub": c.proposed_stub,
            "insert_after": c.insert_after,
            "safe_to_insert": c.safe_to_insert,
            "skip_reason": c.skip_reason,
            "description": c.description,
            "import_needed": _local_import_hint(os.path.splitext(rel)[1]),
        })
    validated, failed = apply_stub_insertions_to_clone(stub_insertions, source_dir)
    fix_table = [
        {
            "policy": "guardrail_stub",
            "description": (s.get("description") or "")[:200],
            "file": s.get("file", ""),
        }
        for s in stub_insertions
        if s.get("status") == "detected" and (s.get("file") or "") in validated
    ]
    logger.info(
        "Local insertion-point scan: %d candidate(s) found, %d file(s) applied",
        len(candidates), len(validated),
    )
    return validated, failed, fix_table


def try_local_stub_insertions_from_checkout(
    source_dir: str,
    file_list: List[str],
    violations: List[Dict[str, Any]],
    *,
    lineaje_pat: str = "",
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]], Optional[str]]:
    """Fail-open wrapper: a missing scanner is a silent skip, not a scan error."""
    if not _ensure_insertion_point_scanner_on_path():
        logger.info(
            "Skipping local stub fallback — insertion_point_scanner.py is not "
            "next to this script (standalone GHA deploy)"
        )
        return {}, [], [], None
    try:
        validated, failed, table = local_stub_insertions_from_checkout(
            source_dir, file_list, violations, lineaje_pat=lineaje_pat,
        )
        return validated, failed, table, None
    except Exception as exc:
        logger.warning("Local stub insertion failed: %s", exc)
        return {}, [], [], None


# ===========================================================================
# Parallel batch scan
# ===========================================================================

def parallel_batch_scan(
    batches: List[List[str]],
    source_dir: str,
    temp_dir: str,
    source_code_repo: str,
    branch: str,
    head_sha: str,
    run_id: str,
    server_url: str,
    bearer_getter: Callable[[], str],
    manifest_files: Optional[List[str]] = None,
    max_workers: int = MAX_SCAN_WORKERS,
) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, str]], int, List[str], str, List[Dict[str, Any]]]:
    all_violations: List[Dict[str, Any]] = []
    all_reports: List[str] = []
    all_aibom: List[Dict[str, str]] = []
    aibom_seen: set = set()
    failed_batch_count = 0
    failure_details: List[str] = []
    enforce_service_url = ""
    all_stub_insertions: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def _scan_one(
        batch_idx: int,
        batch_files: List[str],
        *,
        is_last_batch: bool = True,
    ) -> Tuple[int, Dict[str, Any]]:
        logger.info("Batch %d/%d: %d files", batch_idx, len(batches), len(batch_files))
        archive_path = create_batch_archive(
            source_dir, temp_dir, batch_files,
            source_code_repo, branch, head_sha, batch_idx,
            # Do not classify manifests here — mcp_server.py routes them to CLI Integration.
            manifest_files=None,
        )
        result = run_mcp_scan(
            server_url, bearer_getter, source_code_repo, branch, batch_files, archive_path,
            head_sha=head_sha, is_last_batch=is_last_batch,
        )
        return batch_idx, result

    def _collect(batch_idx: int, mcp_result: Dict[str, Any]) -> None:
        nonlocal enforce_service_url
        err = (mcp_result.get("error") or "").strip()
        if mcp_result.get("success") is False or err:
            raise RuntimeError(err or f"analyze_uploaded_archive failed: {mcp_result}")
        batch_violations = list(mcp_result.get("violations") or [])
        # Older servers emptied remediations and did not yet return violations —
        # keep a file-only fallback so we can still insert stubs.
        if not batch_violations:
            batch_violations = [
                {k: v for k, v in a.items() if k != "fix_code"}
                for a in (mcp_result.get("remediation_actions") or [])
                if a.get("file")
            ]
        batch_report = mcp_result.get("report", "")
        batch_aibom = mcp_result.get("aibom", [])
        batch_enforce = (mcp_result.get("enforce_service_url") or "").strip()
        batch_stub_insertions = _stub_insertions_from_mcp_result(mcp_result)
        logger.info(
            "Batch %d/%d done: status=%s violations=%d aibom=%d enforce=%s stub_insertions=%d",
            batch_idx, len(batches), mcp_result.get("status", "unknown"),
            len(batch_violations), len(batch_aibom),
            batch_enforce or "(none)", len(batch_stub_insertions),
        )
        with lock:
            all_violations.extend(batch_violations)
            if batch_enforce:
                enforce_service_url = batch_enforce
            if batch_report:
                all_reports.append(batch_report)
            for entry in batch_aibom:
                key = (entry.get("name", ""), entry.get("source_file", ""))
                if key not in aibom_seen:
                    aibom_seen.add(key)
                    all_aibom.append(entry)
            all_stub_insertions.extend(batch_stub_insertions)
            all_stub_insertions[:] = _dedupe_stub_insertions(all_stub_insertions)

    def _run_and_collect(
        batch_idx: int,
        batch_files: List[str],
        *,
        is_last_batch: bool = True,
        retry_on_failure: bool = False,
        _split_label: str = "",
    ) -> None:
        label = f"{batch_idx}{_split_label}"
        try:
            _, mcp_result = _scan_one(batch_idx, batch_files, is_last_batch=is_last_batch)
            _collect(batch_idx, mcp_result)
        except BaseException as exc:
            if _is_payload_too_large(exc) and len(batch_files) > 1:
                # The proxy/gateway in front of the MCP endpoint rejected the
                # request body itself (413) — get_upload_url's own size guard
                # never even ran. Retrying the SAME payload would just 413
                # again (unlike a transient network blip, this is
                # deterministic), so split this batch in half and retry each
                # half instead. UNIFAI_FILE_BATCH_SIZE stays file-count-based
                # (unchanged) — this only kicks in for the rare batch whose
                # particular files happen to be big enough to still exceed the
                # transport limit. Halves recurse through this same function,
                # so a half that's STILL too large keeps splitting on its own.
                mid = len(batch_files) // 2
                first_half, second_half = batch_files[:mid], batch_files[mid:]
                logger.warning(
                    "Batch %s: 413 Request Entity Too Large (%d files) — "
                    "splitting into %d + %d files and retrying each half",
                    label, len(batch_files), len(first_half), len(second_half),
                )
                # Only the half that inherits is_last_batch actually finalizes
                # the scan's accumulated upload — the other half is never the
                # literal last thing to run for this batch, regardless of
                # whether the ORIGINAL (unsplit) batch was the final one.
                _run_and_collect(
                    batch_idx, first_half, is_last_batch=False,
                    retry_on_failure=retry_on_failure, _split_label=_split_label + "a",
                )
                _run_and_collect(
                    batch_idx, second_half, is_last_batch=is_last_batch,
                    retry_on_failure=retry_on_failure, _split_label=_split_label + "b",
                )
                return
            if retry_on_failure:
                # This is the one call that finalizes the whole scan's
                # accumulated entities/findings upload server-side (see
                # uploader.py's upload_pipeline_results_batched) — if it never
                # lands, every already-buffered batch is stuck server-side and
                # never reaches S3 at all. One retry here is cheap insurance
                # against a transient network blip; if the first attempt
                # actually landed server-side and only the response was lost,
                # the content-fingerprint duplicate guard in uploader.py makes
                # the retry a safe no-op PUT-wise rather than a second upload.
                logger.warning(
                    "Batch %s (final) failed, retrying once — this call finalizes "
                    "the whole scan's upload: %s", label, exc,
                )
                try:
                    _, mcp_result = _scan_one(batch_idx, batch_files, is_last_batch=is_last_batch)
                    _collect(batch_idx, mcp_result)
                except BaseException as exc2:
                    exc = exc2
                else:
                    return
            nonlocal failed_batch_count
            failed_batch_count += 1
            # Unwrap ExceptionGroup / TaskGroup to surface the real cause
            cause = exc
            if hasattr(exc, "exceptions") and exc.exceptions:
                cause = exc.exceptions[0]
                if hasattr(cause, "exceptions") and cause.exceptions:
                    cause = cause.exceptions[0]
            detail = f"Batch {label}/{len(batches)} failed: {type(cause).__name__}: {cause}"
            logger.error("%s", detail)
            logger.debug("Full exception:", exc_info=exc)
            failure_details.append(detail)
            if retry_on_failure:
                logger.error(
                    "Batch %s (final) failed after retry — every already-buffered batch "
                    "for this scan will NOT be uploaded (see upload_pipeline_results_batched's "
                    "no-durability tradeoff)", label,
                )

    if not batches:
        return all_violations, all_reports, all_aibom, failed_batch_count, failure_details, enforce_service_url, all_stub_insertions

    total_batches = len(batches)

    # Batch 1 runs alone, first — every batch's get_upload_url call resolves
    # (or creates) the SCIM project for this repo+branch+commit via
    # get_sbom_id server-side, with no idempotency guarantee across
    # concurrent callers (see mcp_server.py's own comment on this race).
    # Running batches 2..N concurrently with batch 1 means N racing
    # "does this project exist yet?" checks, each seeing "no" and each
    # POSTing a create — duplicate project rows for one repo+branch+commit.
    # Scanning batch 1 to completion first means the project already exists
    # by the time the rest start, so they resolve (not create) it instead.
    logger.info("Batch 1/%d runs first (alone) so the SCIM project exists before the rest scan in parallel", total_batches)
    # Single-batch scan: batch 1 is also the only (and thus final) batch —
    # upload immediately, same as today. Multi-batch: batch 1 buffers,
    # server-side, like every other non-final batch.
    _run_and_collect(1, batches[0], is_last_batch=(total_batches == 1))

    remaining = list(enumerate(batches[1:], 2))
    if remaining:
        # The literal last batch (by index, not by completion order) must run
        # only after every other batch has already finished and buffered its
        # data server-side (see upload_pipeline_results_batched) — batches
        # completing out of order among themselves is fine, but finalizing
        # before a slower non-final batch has landed would silently drop that
        # batch's data from the scan forever. So: run every batch except the
        # last one in parallel and WAIT for all of them, then run the last
        # one alone, is_last_batch=True.
        middle, (final_idx, final_files) = remaining[:-1], remaining[-1]
        if middle:
            workers = min(len(middle), max_workers)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [
                    executor.submit(_run_and_collect, idx, files, is_last_batch=False)
                    for idx, files in middle
                ]
                for future in as_completed(futures):
                    future.result()  # _run_and_collect already caught/recorded its own failure

        logger.info(
            "Batch %d/%d runs last (alone, after every other batch has completed) to "
            "finalize this scan's single accumulated entities/findings upload",
            final_idx, total_batches,
        )
        _run_and_collect(final_idx, final_files, is_last_batch=True, retry_on_failure=True)

    return all_violations, all_reports, all_aibom, failed_batch_count, failure_details, enforce_service_url, all_stub_insertions

# ===========================================================================
# JSON output
# ===========================================================================

# Human report must not include stub-insertion write-ups (PR body or report.json).
_STUB_REPORT_HEADINGS = (
    "## UniFAI Guardrail Stub Insertion",
    "## Guardrail Stub Insertions",
    "## SECTION 2: Guardrail Stub Coverage",
)


def _strip_stub_insertion_markdown(report: str) -> str:
    """Drop stub-insertion sections from the policy report markdown."""
    if not report:
        return ""
    parts = re.split(r"(?=^## )", report, flags=re.MULTILINE)
    kept: List[str] = []
    for part in parts:
        if any(part.startswith(h) for h in _STUB_REPORT_HEADINGS):
            continue
        kept.append(part)
    text = "".join(kept)
    text = re.sub(r"\n---\s*(?=\n*$)", "\n", text)
    text = re.sub(r"\n---\s*\n+(?=\n## |\n### |\Z)", "\n\n", text)
    return text.strip() + ("\n" if text.strip() else "")


def build_json_output(
    *,
    status: str,
    repo: str,
    branch: str,
    head_sha: str,
    source_code_repo: str,
    files_scanned: int,
    batches: int,
    failed_batches: int,
    violations: List[Dict[str, Any]],
    aibom: Optional[List[Dict[str, str]]] = None,
    report: str = "",
    remediation_pr: Optional[int] = None,
    remediation_branch: str = "",
    failed_remediation_files: Optional[List[str]] = None,
    scan_errors: Optional[List[str]] = None,
    enforce_service_url: str = "",
) -> Dict[str, Any]:
    return {
        "status": status,
        "scan_metadata": {
            "repo": repo,
            "branch": branch,
            "head_sha": head_sha,
            "source_code_repo": source_code_repo,
            "scanned_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": files_scanned,
            "batches": batches,
            "failed_batches": failed_batches,
        },
        "report": _strip_stub_insertion_markdown(report),
        "violations": violations,
        "aibom": aibom or [],
        "enforce_service_url": enforce_service_url,
        "remediation_pr": remediation_pr,
        "remediation_branch": remediation_branch,
        "failed_remediation_files": failed_remediation_files or [],
        "scan_errors": scan_errors or [],
    }


def _positive_line(raw: Any) -> int:
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def _norm_report_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lstrip("./").strip()


def _iter_violating_code_items(v: Dict[str, Any]) -> List[Any]:
    items: List[Any] = []
    for raw in (v.get("violating_code"),):
        if isinstance(raw, dict):
            items.append(raw)
        elif isinstance(raw, list):
            items.extend(raw)
        elif isinstance(raw, str) and raw.strip():
            items.append(raw)
    meta = v.get("metadata") if isinstance(v.get("metadata"), dict) else {}
    nested = meta.get("violating_code")
    if isinstance(nested, dict):
        items.append(nested)
    elif isinstance(nested, list):
        items.extend(nested)
    elif isinstance(nested, str) and nested.strip():
        items.append(nested)
    return items


def _vc_line(vc: Any) -> int:
    if isinstance(vc, dict):
        return _positive_line(
            vc.get("line")
            or vc.get("line_no")
            or vc.get("lineno")
            or vc.get("start_line")
            or vc.get("line_number")
        )
    return _positive_line(getattr(vc, "line", 0))


def _structured_violation_lines(v: Dict[str, Any]) -> List[int]:
    """Collect 1-indexed lines already present on the finding (no disk search)."""
    nums: List[int] = []
    seen: set = set()

    def _add(raw: Any) -> None:
        n = _positive_line(raw)
        if n and n not in seen:
            seen.add(n)
            nums.append(n)

    loc = v.get("location") if isinstance(v.get("location"), dict) else {}
    _add(loc.get("start_line") or loc.get("line") or loc.get("line_number"))
    evidence = v.get("evidence") if isinstance(v.get("evidence"), dict) else {}
    _add(evidence.get("line") or evidence.get("line_number"))
    before = evidence.get("before") if isinstance(evidence.get("before"), dict) else {}
    ctx = before.get("context") if isinstance(before.get("context"), dict) else {}
    _add(ctx.get("line") or ctx.get("line_number") or ctx.get("start_line"))
    for vc in _iter_violating_code_items(v):
        _add(_vc_line(vc))
    meta = v.get("metadata") if isinstance(v.get("metadata"), dict) else {}
    _add(v.get("line"))
    _add(v.get("line_number"))
    _add(v.get("start_line"))
    _add(v.get("lineno"))
    _add(v.get("line_no"))
    _add(meta.get("line_number"))
    _add(meta.get("line"))
    _add(meta.get("start_line"))
    return nums


def _search_snippet_line(repo_root: str, filename: str, snippet: str) -> int:
    """1-indexed line of *snippet* in *filename* under *repo_root*, or 0."""
    search_text = (snippet or "").strip()
    if not repo_root or not filename or not search_text:
        return 0
    root = pathlib.Path(repo_root)
    file_path = pathlib.Path(filename)
    if not file_path.is_file():
        file_path = root / filename
    if not file_path.is_file():
        base = os.path.basename(filename)
        if base:
            try:
                for candidate in root.rglob(base):
                    if candidate.is_file():
                        file_path = candidate
                        break
            except OSError:
                pass
    if not file_path.is_file():
        return 0
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return 0

    snippet_lines = [ln.strip() for ln in search_text.splitlines() if ln.strip()]
    if snippet_lines:
        first = snippet_lines[0]
        for i, line in enumerate(lines):
            if first == line.strip() or first in line:
                if len(snippet_lines) == 1:
                    return i + 1
                if i + len(snippet_lines) <= len(lines) and all(
                    lines[i + j].strip() == snippet_lines[j]
                    for j in range(len(snippet_lines))
                ):
                    return i + 1
    collapsed = re.sub(r"\s+", " ", search_text)
    if len(collapsed) >= 8:
        for i, line in enumerate(lines):
            if collapsed in re.sub(r"\s+", " ", line):
                return i + 1
    return 0


def _snippet_lines_for_violation(v: Dict[str, Any], repo_root: str) -> List[int]:
    if not repo_root:
        return []
    filename = str(v.get("file") or v.get("file_path") or v.get("filepath") or "")
    nums: List[int] = []
    seen: set = set()
    for vc in _iter_violating_code_items(v):
        if isinstance(vc, dict):
            filename = filename or str(vc.get("filename") or vc.get("file") or "")
            snippet = str(vc.get("code") or vc.get("snippet") or vc.get("text") or "")
        elif isinstance(vc, str):
            snippet = vc
        else:
            snippet = str(getattr(vc, "code", "") or "")
        found = _search_snippet_line(repo_root, filename, snippet)
        if found and found not in seen:
            seen.add(found)
            nums.append(found)
    return nums


def _stub_lines_for_violation(
    v: Dict[str, Any],
    stubs: Optional[List[Dict[str, Any]]],
) -> List[int]:
    if not stubs:
        return []
    file_ = _norm_report_path(str(v.get("file") or ""))
    if not file_:
        for vc in _iter_violating_code_items(v):
            if isinstance(vc, dict):
                file_ = _norm_report_path(str(vc.get("filename") or vc.get("file") or ""))
                if file_:
                    break
    pid = str(v.get("policy_id") or "").strip()
    matched: List[int] = []
    file_only: List[int] = []
    seen_m: set = set()
    seen_f: set = set()
    for stub in stubs:
        if not isinstance(stub, dict):
            continue
        sf = _norm_report_path(str(stub.get("file") or ""))
        if not file_ or not sf:
            continue
        if sf != file_ and not sf.endswith("/" + file_) and not file_.endswith("/" + sf):
            continue
        n = _positive_line(stub.get("line"))
        if not n:
            continue
        if n not in seen_f:
            seen_f.add(n)
            file_only.append(n)
        details = stub.get("policy_details") or stub.get("candidate_policies") or []
        ids = {
            str(d.get("policy_id") or "")
            for d in details
            if isinstance(d, dict)
        }
        if pid and pid in ids and n not in seen_m:
            seen_m.add(n)
            matched.append(n)
    return matched or file_only


def _violation_line_numbers(
    v: Dict[str, Any],
    *,
    repo_root: str = "",
    stubs: Optional[List[Dict[str, Any]]] = None,
) -> List[int]:
    nums = _structured_violation_lines(v)
    if nums:
        return nums
    nums = _snippet_lines_for_violation(v, repo_root)
    if nums:
        return nums
    return _stub_lines_for_violation(v, stubs)


def _enrich_violation_line_numbers(
    violations: List[Dict[str, Any]],
    repo_root: str = "",
    stubs: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Fill ``line`` / ``violating_code[].line`` when MCP left them as 0."""
    for v in violations or []:
        if not isinstance(v, dict):
            continue
        nums = _violation_line_numbers(v, repo_root=repo_root, stubs=stubs)
        if not nums:
            continue
        if _positive_line(v.get("line")) <= 0:
            v["line"] = nums[0]
        vcs = v.get("violating_code")
        if not isinstance(vcs, list):
            continue
        for i, vc in enumerate(vcs):
            if isinstance(vc, dict) and _vc_line(vc) <= 0:
                vc["line"] = nums[min(i, len(nums) - 1)]


def _violation_line_display(
    v: Dict[str, Any],
    *,
    repo_root: str = "",
    stubs: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """1-indexed source line(s) for a finding, or em-dash when unknown."""
    nums = _violation_line_numbers(v, repo_root=repo_root, stubs=stubs)
    if not nums:
        return "—"
    return ", ".join(str(n) for n in nums)


def _violation_file_line_and_control(v: Dict[str, Any]) -> Tuple[str, str, str]:
    vcs = v.get("violating_code") or []
    first_vc = vcs[0] if vcs and isinstance(vcs[0], dict) else {}
    meta = v.get("metadata") if isinstance(v.get("metadata"), dict) else {}
    file_ = (
        v.get("file")
        or v.get("file_path")
        or first_vc.get("filename")
        or meta.get("filename")
        or "(unknown)"
    )
    control = v.get("policy_name") or v.get("control") or v.get("policy_id") or "(unknown)"
    return str(file_), _violation_line_display(v), str(control)


def format_violations_markdown_table(
    violations: List[Dict[str, Any]],
    *,
    max_files: int = 0,
) -> str:
    """GitHub-flavored Markdown table: File | Line | Policy (one row per finding)."""
    rows: List[Tuple[str, str, str]] = []
    files: set = set()
    for v in violations:
        file_, line, control = _violation_file_line_and_control(v)
        files.add(file_)
        rows.append((file_, line, control))
    if not rows:
        return ""

    def _line_sort_key(line: str) -> int:
        if not line or line == "—":
            return 0
        try:
            return int(str(line).split(",", 1)[0].strip())
        except ValueError:
            return 0

    rows.sort(key=lambda r: (r[0], _line_sort_key(r[1]), r[2]))
    extra = 0
    if max_files and len(rows) > max_files:
        extra = len(rows) - max_files
        rows = rows[:max_files]
    lines = [
        f"**{len(violations)} violation(s) across {len(files)} file(s)**",
        "",
        "| File | Line | Policy |",
        "|------|------|--------|",
    ]
    for file_, line, control in rows:
        lines.append(f"| `{file_}` | {line} | {control} |")
    if extra:
        lines.append(f"| _…and {extra} more violation(s)_ | — | _see full scan report_ |")
    return "\n".join(lines)


def _extract_markdown_section(report: str, heading_substr: str) -> str:
    """Return the ``### …`` section whose heading contains *heading_substr*."""
    if not report or not heading_substr:
        return ""
    lines = report.splitlines()
    start: Optional[int] = None
    for i, line in enumerate(lines):
        if line.startswith("### ") and heading_substr in line:
            start = i
            break
    if start is None:
        return ""
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("### "):
            end = j
            break
    return "\n".join(lines[start:end]).strip()


def _clip_github_report(report: str, max_chars: int = 40_000) -> str:
    """Trim a markdown chunk to *max_chars*; close dangling fences."""
    text = (report or "").strip()
    if not text:
        return ""
    if len(text) <= max_chars:
        clipped = text
        truncated = False
    else:
        budget = max(0, max_chars - len(_PR_BODY_TRUNCATION_NOTE))
        clipped = text[:budget]
        truncated = True
    if clipped.count("```") % 2 == 1:
        clipped += "\n```\n"
    if truncated:
        clipped += _PR_BODY_TRUNCATION_NOTE
    return clipped


def _fit_github_pr_body(text: str, max_chars: int = GITHUB_PR_BODY_SAFE_LIMIT) -> str:
    """Hard-cap a PR body so GitHub's 65536-char POST /pulls does not 422."""
    text = text or ""
    if len(text) <= max_chars:
        return text
    note = _PR_BODY_TRUNCATION_NOTE
    fence = "\n```\n"
    budget = max(0, max_chars - len(note))
    clipped = text[:budget]
    if clipped.count("```") % 2 == 1:
        budget = max(0, max_chars - len(note) - len(fence))
        clipped = text[:budget] + fence
    return clipped + note


def _build_fix_pr_body(
    *,
    branch: str,
    sha_short: str,
    report: str = "",
    violations: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """PR description: the LINEAJE AI POLICY REPORT, verbatim, and nothing else —
    no extra status header before it, no duplicated violations table, no second
    copy of the report folded into a details block after it. Stub files are on
    the branch itself — they are not listed in this body."""
    report = _strip_stub_insertion_markdown(report)
    if "## No Files Changed" in (report or ""):
        report = ""
    if not report.strip():
        return "No violations found."
    return _fit_github_pr_body(_clip_github_report(report, max_chars=GITHUB_PR_BODY_SAFE_LIMIT - 200))


def print_human_output(output: Dict[str, Any]) -> None:
    status = output.get("status", "unknown")
    violations = output.get("violations", [])
    scan_errors = output.get("scan_errors", [])
    metadata = output.get("scan_metadata", {})
    scanned_at = metadata.get("scanned_at", "")
    branch = metadata.get("branch", "")
    repo = metadata.get("repo") or ""
    rem_pr = output.get("remediation_pr")

    if status == "compliant":
        status_label = "✅ Compliant"
    elif status == "violations_found":
        status_label = "❌ Not Compliant"
    else:
        status_label = status

    print("# UnifAI Security Report")
    print()
    print(f"**Status:** {status_label}")
    if branch:
        print(f"**Branch:** `{branch}`")
    if scanned_at:
        print(f"**Scanned at:** {scanned_at}")
    if rem_pr:
        print(f"**Remediation PR:** https://github.com/{repo}/pull/{rem_pr}")

    if scan_errors:
        print("\n**Errors:**")
        for err in scan_errors:
            print(f"- {err}")
        print()

    if not violations:
        if status == "compliant":
            print("\nNo violations found.")
        return

    print()
    print(format_violations_markdown_table(violations, max_files=40))


# ===========================================================================
# Patch application (ported from veracode_repo_scan.py, no external deps)
# ===========================================================================

def _normalize_for_patch_match(s: str) -> str:
    return re.sub(r"[ \t]+", " ", s)


def _apply_fix_entry(content: str, original: str, replacement: str) -> Tuple[str, bool]:
    if not original:
        return content, False

    if original in content:
        return content.replace(original, replacement, 1), True

    orig_stripped = original.strip()
    if orig_stripped and orig_stripped in content:
        return content.replace(orig_stripped, replacement, 1), True

    norm_orig = _normalize_for_patch_match(orig_stripped)
    norm_content = _normalize_for_patch_match(content)
    idx = norm_content.find(norm_orig)
    if idx != -1:
        orig_len = len(orig_stripped)
        real_idx = 0
        norm_walked = 0
        for ci, ch in enumerate(content):
            if norm_walked >= idx:
                real_idx = ci
                break
            norm_walked += len(_normalize_for_patch_match(ch))
        else:
            real_idx = len(content)
        sub = content[real_idx: real_idx + orig_len + 50]
        if orig_stripped in sub:
            actual_idx = content.find(orig_stripped, real_idx)
            if actual_idx != -1:
                return content[:actual_idx] + replacement + content[actual_idx + len(orig_stripped):], True

    orig_lines = [l for l in orig_stripped.splitlines() if l.strip()]
    if orig_lines:
        anchor = orig_lines[0].strip()
        if len(anchor) > 15:
            anchor_idx = content.find(anchor)
            if anchor_idx != -1:
                end_search = content.find(orig_lines[-1].strip(), anchor_idx) if len(orig_lines) > 1 else anchor_idx
                if end_search != -1:
                    end_idx = end_search + len(orig_lines[-1].strip())
                    found_block = content[anchor_idx:end_idx]
                    if len(found_block) < len(orig_stripped) * 2:
                        return content[:anchor_idx] + replacement + content[end_idx:], True

    return content, False


def _norm_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def _resolve_source_file(source_dir: str, filepath: str, file_list: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a violation filepath to (rel_path, content) from the live checkout."""
    raw = filepath.strip()
    if not raw:
        return None, None
    norm_fp = _norm_rel_path(raw)
    root = pathlib.Path(source_dir)

    candidate = root / raw
    if candidate.is_file():
        return norm_fp, candidate.read_text(errors="replace")

    # Try normalised path
    candidate2 = root / norm_fp
    if candidate2.is_file():
        return norm_fp, candidate2.read_text(errors="replace")

    # Basename fallback
    base = pathlib.Path(norm_fp).name
    matches = [f for f in file_list if pathlib.Path(f).name == base]
    if len(matches) == 1:
        full = root / matches[0]
        if full.is_file():
            return _norm_rel_path(matches[0]), full.read_text(errors="replace")

    logger.warning("Cannot resolve remediation file %r in source dir", raw)
    return None, None


def apply_pipeline_fix_code_to_clone(
    remediation_actions: List[Dict[str, Any]],
    source_dir: str,
    file_list: List[str],
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Apply fix_code patches from MCP remediation_actions to checked-out files.

    Returns (validated_fixes, failed_files, fix_table_rows).
    """
    validated_fixes: Dict[str, str] = {}
    failed_files: List[str] = []
    fix_table_rows: List[Dict[str, str]] = []

    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for action in remediation_actions:
        fp = (action.get("file") or "").strip()
        if fp:
            by_file.setdefault(fp, []).append(action)

    for filepath, actions in by_file.items():
        has_fix_code = any(action.get("fix_code") for action in actions)
        if not has_fix_code:
            failed_files.append(filepath)
            continue

        rel_path, original_content = _resolve_source_file(source_dir, filepath, file_list)
        if rel_path is None or original_content is None:
            failed_files.append(filepath)
            continue

        content = original_content
        patch_applied = False
        for action in actions:
            for fix_entry in (action.get("fix_code") or []):
                original = fix_entry.get("original") or ""
                replacement = fix_entry.get("replacement", "")
                if not original.strip():
                    continue
                content, applied = _apply_fix_entry(content, original, replacement)
                if applied:
                    patch_applied = True
                else:
                    logger.debug(
                        "Patch not applied for %r — original snippet (%d chars) not found",
                        filepath, len(original),
                    )

        if patch_applied and content != original_content:
            validated_fixes[rel_path] = content
            for action in actions:
                fix_table_rows.append({
                    "policy": action.get("control", ""),
                    "description": (action.get("instruction") or "")[:200],
                    "file": filepath,
                })
        else:
            logger.warning("No patch applied for %r — snippets did not match file content", filepath)
            failed_files.append(filepath)

    return validated_fixes, failed_files, fix_table_rows


# ===========================================================================
# Remediation PR creation
# ===========================================================================

class _GhaGitHubClient:
    """Minimal GitHub REST client for the standalone GHA scanner.

    This script is copied alone into ``.lineaje-scanner/scripts/`` — it must
    not import ``scm_client.py``.
    """

    def __init__(self, token: str, base_url: str = "") -> None:
        self.token = token
        self.base_url = (
            base_url
            or os.environ.get("GITHUB_API_URL")
            or "https://api.github.com"
        ).rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        *,
        expected_errors: Optional[set] = None,
    ) -> Any:
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "UniFAI-GHA-Scanner/1.0",
        }
        data = json.dumps(body).encode() if body else None
        if data:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            err = exc.read().decode("utf-8", errors="replace")[:500]
            if expected_errors and exc.code in expected_errors:
                logger.debug("GitHub API %s %s → %s (expected): %s", method, url, exc.code, err)
            else:
                logger.error("GitHub API %s %s → %s: %s", method, url, exc.code, err)
            raise

    def create_branch(self, repo: str, branch_name: str, from_sha: str) -> None:
        self._request("POST", f"/repos/{repo}/git/refs", {
            "ref": f"refs/heads/{branch_name}",
            "sha": from_sha,
        })

    def get_file_blob_sha(self, repo: str, path: str, ref: str) -> Optional[str]:
        encoded_path = urllib.parse.quote(path, safe="/")
        qref = urllib.parse.quote(ref, safe="")
        try:
            data = self._request(
                "GET",
                f"/repos/{repo}/contents/{encoded_path}?ref={qref}",
                expected_errors={404},
            )
            if isinstance(data, dict) and data.get("type") == "file" and data.get("sha"):
                return str(data["sha"])
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        return None

    def commit_file(
        self,
        repo: str,
        branch: str,
        path: str,
        content: bytes,
        message: str,
        sha: Optional[str] = None,
    ) -> str:
        if sha is None:
            sha = self.get_file_blob_sha(repo, path, branch)
        payload: Dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content).decode(),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        encoded_path = urllib.parse.quote(path, safe="/")
        resp = self._request("PUT", f"/repos/{repo}/contents/{encoded_path}", payload)
        return resp["commit"]["sha"]

    def create_pull_request(
        self,
        repo: str,
        title: str,
        head: str,
        base: str,
        body: str,
        **_kw: Any,
    ) -> int:
        resp = self._request("POST", f"/repos/{repo}/pulls", {
            "title": title,
            "head": head,
            "base": base,
            "body": body,
        })
        return resp["number"]


def _create_fix_pr(
    github_token: str,
    repo: str,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    report: str = "",
    failed_files: Optional[List[str]] = None,
    violations: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Optional[int], str, str]:
    """Commit stub + enforce-API files to a branch and open a PR.

    Returns ``(pr_number_or_None, remediation_branch, error_or_empty)``.
    """
    if not validated_fixes:
        return None, "", ""

    if not head_sha:
        logger.error(
            "Cannot create remediation branch: head_sha is empty. "
            "Pass --head-sha or ensure $GITHUB_SHA is set in the environment."
        )
        return None, "", "Cannot create remediation branch: head_sha is empty"

    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)
    sha_short = head_sha[:7]
    timestamp = time.strftime("%m%d%H%M")
    remediation_branch = f"{REMEDIATION_BRANCH_PREFIX}-{safe_branch.replace('/', '-')}-{sha_short}-{timestamp}"

    scm = _GhaGitHubClient(token=github_token)

    # Resolve short SHA to full 40-char SHA (GitHub's /git/refs API requires it)
    if len(head_sha) < 40:
        try:
            commit_data = scm._request("GET", f"/repos/{repo}/commits/{head_sha}")
            head_sha = commit_data["sha"]
        except Exception as exc:
            logger.warning("Could not resolve short SHA %s: %s", head_sha, exc)

    try:
        logger.info("Creating remediation branch %s from %s", remediation_branch, sha_short)
        scm.create_branch(repo, remediation_branch, head_sha)
    except Exception as exc:
        logger.error("Failed to create/verify remediation branch: %s", exc)
        return None, remediation_branch, f"Failed to create remediation branch: {exc}"

    committed: List[str] = []
    for filepath, content in validated_fixes.items():
        blob_sha: Optional[str] = None
        try:
            blob_sha = scm.get_file_blob_sha(repo, filepath, head_sha)
        except Exception:
            pass
        policies = ", ".join({r["policy"] for r in fix_table if r["file"] == filepath}) or "policy violations"
        message = f"fix({filepath}): remediate {policies} [unifai-gha-scan]"
        try:
            scm.commit_file(repo, remediation_branch, filepath, content.encode("utf-8"), message, sha=blob_sha)
            committed.append(filepath)
            logger.info("Committed fix: %s", filepath)
        except Exception as exc:
            logger.error("Failed to commit %s: %s", filepath, exc)

    if not committed:
        logger.warning("No files committed — skipping PR creation")
        return None, remediation_branch, "No files committed — skipping PR creation"

    title = f"[unifai-bot] fix: AI policy remediation with stubs and guardrail for {branch}@{sha_short}"
    pr_body = _build_fix_pr_body(
        branch=branch,
        sha_short=sha_short,
        report=report,
        violations=violations,
    )
    logger.info(
        "PR body: %d chars, report=%s, violations=%d",
        len(pr_body), "yes" if (report or "").strip() else "no", len(violations or []),
    )

    try:
        pr_number = scm.create_pull_request(repo, title, remediation_branch, branch, pr_body)
        logger.info("Created remediation PR #%d", pr_number)
        return pr_number, remediation_branch, ""
    except Exception as exc:
        logger.error("Failed to create remediation PR (%d chars): %s", len(pr_body), exc)
        fallback = _build_fix_pr_body(
            branch=branch,
            sha_short=sha_short,
            report="",
            violations=[],
        )
        try:
            pr_number = scm.create_pull_request(repo, title, remediation_branch, branch, fallback)
            logger.warning(
                "Created remediation PR #%d with fallback body after: %s", pr_number, exc,
            )
            return pr_number, remediation_branch, ""
        except Exception as exc2:
            logger.error("Fallback PR creation also failed: %s", exc2)
            return (
                None,
                remediation_branch,
                f"Failed to create remediation PR for `{remediation_branch}`: {exc2}",
            )


# ===========================================================================
# Main scan orchestration
# ===========================================================================

_SELF_SCAN_REPO_SLUGS = frozenset({"aipo-mcp-server"})


def _is_self_scan_target(source_code_repo: str) -> bool:
    """True if ``source_code_repo`` names this scanning tool's own repo.

    This script scans customer/target repos on a caller's behalf — it must
    never scan (and upload results for) itself. A self-scan that reaches
    the shared production SCM backend creates a real, customer-visible
    "aipo-mcp-server" project entry with no business being there (this
    happened in production). Dev testing against a copy of this tool's own
    code must use a differently-named fork/local path, not this repo's
    real identity.
    """
    repo = (source_code_repo or "").strip().rstrip("/")
    if not repo:
        return False
    if repo.lower().endswith(".git"):
        repo = repo[: -len(".git")]
    slug = repo.rsplit("/", 1)[-1].strip().lower().replace("_", "-")
    return slug in _SELF_SCAN_REPO_SLUGS


def _execute_scan(args: argparse.Namespace) -> int:
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    branch = args.branch or os.environ.get("GITHUB_REF_NAME", "")
    head_sha = args.head_sha or os.environ.get("GITHUB_SHA", "")
    source_path = os.path.abspath(args.source_path)
    server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or MCP_SERVER_URL
    source_code_repo = f"https://github.com/{repo}.git" if repo else source_path

    if _is_self_scan_target(source_code_repo) or _is_self_scan_target(repo):
        logger.error(
            "Refusing to scan %s: this is aipo_mcp_server's own repo. This "
            "tool scans customer/target repos on a caller's behalf and must "
            "never scan (and upload results for) itself.",
            source_code_repo,
        )
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
            scan_errors=[
                f"Refusing to scan {source_code_repo!r}: this is aipo_mcp_server's "
                "own repo, which must never be scanned by this tool."
            ],
        )
        print_human_output(output)
        return 2

    do_clone = getattr(args, "clone", False)
    github_token = (
        (getattr(args, "github_token", None) or "").strip()
        or os.environ.get("GH_TOKEN", "")
        or os.environ.get("GITHUB_TOKEN", "")
    )

    # Validate config
    required = [("GITHUB_REPOSITORY / --repo", repo), ("GITHUB_REF_NAME / --branch", branch)]
    if do_clone:
        # Cloning needs a token unconditionally — there's nothing to scan without it,
        # regardless of whether --create-fix-pr is also set.
        required.append(("GH_TOKEN / GITHUB_TOKEN / --github-token (required with --clone)", github_token))
    if getattr(args, "create_fix_pr", False) and not github_token:
        required.append(("--github-token / $GH_TOKEN / $GITHUB_TOKEN (required with --create-fix-pr)", github_token))
    missing = [n for n, v in required if not v]
    if missing:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Missing required config: {', '.join(missing)}"],
        )
        print_human_output(output)
        return 2

    if do_clone:
        # --clone: fetch repo/branch ourselves instead of assuming --source-path is
        # already a checkout — lets this script run outside a real GHA job (e.g. from
        # a plain VM) without a separate manual clone step.
        clone_dir = tempfile.mkdtemp(prefix="gha-repo-scan-clone-")
        try:
            clone_repository(repo, branch, clone_dir, github_token)
        except Exception as exc:
            shutil.rmtree(clone_dir, ignore_errors=True)
            output = build_json_output(
                status="error", repo=repo, branch=branch, head_sha=head_sha,
                source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
                violations=[], scan_errors=[f"Clone failed: {exc}"],
            )
            print_human_output(output)
            return 1
        atexit.register(shutil.rmtree, clone_dir, ignore_errors=True)
        source_path = clone_dir
        logger.info("Cloned %s@%s into %s — scanning this checkout", repo, branch, clone_dir)

    if not head_sha:
        # Neither --head-sha nor $GITHUB_SHA (the latter is only set inside a real GHA
        # job) — fall back to reading it straight off the checkout being scanned
        # (the fresh clone above, when --clone was used).
        head_sha = _resolve_head_sha_from_source(source_path)

    if getattr(args, "create_fix_pr", False) and not head_sha:
        # head_sha is only load-bearing when we're about to create a remediation branch off it —
        # an empty value there produces a confusing cascade of GitHub API 422s, not a clear error.
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
            scan_errors=["Missing required config: GITHUB_SHA / --head-sha (required with --create-fix-pr)"],
        )
        print_human_output(output)
        return 2

    try:
        bearer_getter = build_bearer_getter(_scan_refresh_token(args))
        # Eagerly exchange LINEAJE_PAT_TOKEN for an access token now, so a bad/expired
        # refresh token fails fast here instead of after a full scan.
        access_token = bearer_getter()
        logger.info("Auth OK — renew-access-token exchange succeeded (token len=%d)", len(access_token))
    except Exception as exc:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Auth failed: {exc}"],
        )
        print_human_output(output)
        return 2

    run_id = time.strftime("%Y%m%d_%H%M%S")
    scan_start = time.perf_counter()

    logger.info("Scanning source path: %s (repo=%s branch=%s sha=%s)", source_path, repo, branch, head_sha[:7] if head_sha else "?")

    # Step 1: Collect files
    file_list = collect_repo_files(source_path)
    if not file_list:
        logger.info("No scannable files found")
        output = build_json_output(
            status="compliant", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
        )
        print_human_output(output)
        return 0

    batch_size = _batch_size(len(file_list))
    batches = [file_list[i: i + batch_size] for i in range(0, len(file_list), batch_size)]
    logger.info(
        "Files: %d total → %d batch(es); mcp_server drops dependency manifests "
        "from AIonizer/eval and sends them to CLI Integration",
        len(file_list), len(batches),
    )

    # Step 2: MCP scan
    with tempfile.TemporaryDirectory(prefix="gha-repo-scan-") as temp_dir:
        (
            all_violations, all_reports, all_aibom, failed_batches_count,
            failure_details, enforce_service_url, all_stub_insertions,
        ) = parallel_batch_scan(
            batches=batches,
            source_dir=source_path,
            temp_dir=temp_dir,
            source_code_repo=source_code_repo,
            branch=branch,
            head_sha=head_sha,
            run_id=run_id,
            server_url=server_url,
            bearer_getter=bearer_getter,
        )

    elapsed = time.perf_counter() - scan_start
    logger.info(
        "Scan complete in %.1fs: %d violation(s), %d AIBOM entry/ies, %d failed batch(es)",
        elapsed, len(all_violations), len(all_aibom), failed_batches_count,
    )

    combined_report = _combine_scan_reports(all_reports)
    _enrich_violation_line_numbers(
        all_violations, repo_root=source_path, stubs=all_stub_insertions,
    )

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details, enforce_service_url=enforce_service_url,
        )
        print_human_output(output)
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    # Step 3: Insert guardrail stubs and create PR.
    # Prefer MCP stub_insertions / patched_files. If --create-fix-pr is set
    # but the server returned nothing applyable, insert locally from
    # violations so a PR still opens. Do NOT apply remediation_actions.
    remediation_pr_number: Optional[int] = None
    remediation_branch = ""
    failed_rem_files: List[str] = []

    # github_token already resolved near the top of this function (also used for --clone).
    should_create_pr = bool(github_token and getattr(args, "create_fix_pr", False))
    validated_fixes: Dict[str, str] = {}
    fix_table: List[Dict[str, str]] = []

    if all_stub_insertions:
        logger.info(
            "STEP 3: Applying %d MCP stub insertion(s)",
            len(all_stub_insertions),
        )
        validated_fixes, failed_rem_files = apply_stub_insertions_to_clone(
            all_stub_insertions, source_path,
        )
        fix_table = [
            {
                "policy": ", ".join(
                    {pd.get("policy_id", "") for pd in (s.get("policy_details") or []) if pd.get("policy_id")}
                ) or "guardrail_stub",
                "description": s.get("description", "")[:200],
                "file": s.get("file", ""),
            }
            for s in all_stub_insertions
            if s.get("status") == "detected" and (s.get("file") or "") in validated_fixes
        ]

    if should_create_pr and not validated_fixes and all_violations:
        logger.info(
            "MCP returned 0 applyable stubs — attempting local insertion-point scan "
            "(%d violation(s))",
            len(all_violations),
        )
        local_fixes, local_failed, local_table, local_err = try_local_stub_insertions_from_checkout(
            source_path,
            file_list,
            all_violations,
            lineaje_pat=_scan_refresh_token(args),
        )
        if local_err:
            logger.warning("%s", local_err)
        validated_fixes = local_fixes
        failed_rem_files.extend(local_failed)
        fix_table = local_table
        if validated_fixes:
            logger.info("Local stub insertion produced %d file(s) to commit", len(validated_fixes))

    if validated_fixes:
        _ensure_refresh_token_in_validated_fixes(
            validated_fixes, _scan_refresh_token(args), source_path,
        )

    if should_create_pr and validated_fixes:
        logger.info("Creating stub PR (%d file(s))", len(validated_fixes))
        try:
            remediation_pr_number, remediation_branch, pr_error = _create_fix_pr(
                github_token, repo, branch, head_sha,
                validated_fixes, fix_table,
                report=combined_report, failed_files=failed_rem_files,
                violations=all_violations,
            )
            if pr_error:
                logger.error("%s", pr_error)
        except Exception as exc:
            logger.error("Stub insertion / PR step failed: %s", exc)
    elif should_create_pr:
        logger.warning(
            "Skipping stub PR — --create-fix-pr was set but there were no stub files "
            "to commit (mcp stub_insertions=%d violations=%d)",
            len(all_stub_insertions), len(all_violations),
        )
    elif all_stub_insertions and not getattr(args, "create_fix_pr", False):
        logger.info("Skipping stub PR — pass --create-fix-pr to insert stubs and open a PR")
    elif all_stub_insertions:
        logger.info("Skipping stub PR — GITHUB_TOKEN / --github-token not set")

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        remediation_pr=remediation_pr_number,
        remediation_branch=remediation_branch,
        failed_remediation_files=failed_rem_files,
        scan_errors=failure_details,
        enforce_service_url=enforce_service_url,
    )
    print_human_output(output)
    return 0

# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lineaje AI Policy Scanner — GitHub Actions edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--source-path", default=".",
        help="Path to the checked-out source code (default: current directory). "
             "Ignored when --clone is set — the fresh clone is scanned instead.",
    )
    parser.add_argument(
        "--clone", action="store_true",
        help="Clone --repo/--branch into a temp dir using --github-token before scanning, "
             "instead of assuming --source-path is already a checkout (default: false). "
             "Lets this script run outside a real GHA job (e.g. a plain VM) without a "
             "separate manual clone step. Requires --github-token (or $GH_TOKEN / "
             "$GITHUB_TOKEN) regardless of --create-fix-pr.",
    )
    parser.add_argument(
        "--repo", default="",
        help="Repository owner/repo slug (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--branch", default="",
        help="Branch name (default: $GITHUB_REF_NAME)",
    )
    parser.add_argument(
        "--head-sha", default="",
        help="Commit SHA (default: $GITHUB_SHA)",
    )
    parser.add_argument(
        "--mcp-server-url", default="",
        help=f"MCP server URL (default: {MCP_SERVER_URL})",
    )
    parser.add_argument(
        "--github-token", default="",
        help="GitHub token for creating remediation PRs (default: $GH_TOKEN then $GITHUB_TOKEN). "
             "If not set, violations are reported but no PR is created.",
    )
    parser.add_argument(
        "--lineaje-pat", default="", dest="lineaje_pat",
        help="Lineaje PAT / refresh token for MCP auth (default: $LINEAJE_PAT_TOKEN). "
             "Inserted guardrail stubs read their own auth from GR_BEARER_TOKEN / "
             "LINEAJE_PAT_TOKEN / LINEAJE_PAT at the customer's own runtime — this "
             "flag only authenticates THIS scan's MCP calls.",
    )
    parser.add_argument(
        "--refresh-token", default="", dest="refresh_token",
        help="Alias for --lineaje-pat.",
    )
    parser.add_argument(
        "--create-fix-pr", default=False, action="store_true",
        help="Create a PR that inserts guardrail stubs and enforce-API config "
             "into the customer codebase (default: false). Does not apply "
             "remediation_actions / fix_code comments.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    # Always show INFO from this logger regardless of --debug
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print_human_output(err)
        return 1


if __name__ == "__main__":
    sys.exit(main())
