from __future__ import annotations
import json
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Iterator, Optional
from urllib.parse import urljoin, urlparse

import requests

from .models import Credentials

_RE_PROJECT_REF = re.compile(r'https://([a-z0-9]{20})\.supabase\.co')
_RE_JWT = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
# New Supabase publishable key format (non-JWT)
_RE_SB_PUBLISHABLE = re.compile(r'sb_publishable_[A-Za-z0-9_-]+')
_RE_CREATE_CLIENT = re.compile(
    r'createClient\s*\(\s*[\'"]https://([a-z0-9]{20})\.supabase\.co[\'"]'
    r'\s*,\s*[\'"]([^\'"]+)[\'"]'
)
_RE_SUPABASE_KEY = re.compile(r'SUPABASE_(?:ANON_)?KEY\s*[=:]\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
_RE_ANON_KEY = re.compile(r'anon[_-]?key[\'"]?\s*[=:]\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
_RE_EDGE_FN = re.compile(r'functions\.invoke\s*\(\s*[\'"]([^\'"]+)[\'"]')
# supabase.from('table') / .rpc('fn') — used when the OpenAPI spec is unavailable
_RE_FROM = re.compile(r'\.from\(\s*[\'"`]([A-Za-z_][A-Za-z0-9_]*)[\'"`]\s*\)')
_RE_RPC = re.compile(r'\.rpc\(\s*[\'"`]([A-Za-z_][A-Za-z0-9_]*)[\'"`]')
# Tuple format: ('https://ref.supabase.co', 'eyJ...' or 'sb_publishable_...')
_RE_TUPLE = re.compile(
    r'\(\s*[\'"]https://([a-z0-9]{20})\.supabase\.co[\'"]'
    r'\s*,\s*[\'"]([^\'"]+)[\'"]'
    r'\s*\)'
)
# Matches url+key as consecutive args without requiring closing paren —
# catches minified calls with a third options argument, e.g. Ps('url', 'key', {...})
_RE_URL_KEY_PAIR = re.compile(
    r'[\'"]https://([a-z0-9]{20})\.supabase\.co[\'"]'
    r'\s*,\s*[\'"]([^\'"]{30,})[\'"]',
    re.DOTALL,
)


def is_valid_supabase_anon_key(token: str) -> bool:
    if _RE_SB_PUBLISHABLE.fullmatch(token):
        return True
    try:
        import jwt
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("role") == "anon"
    except Exception:
        return False


def is_valid_supabase_key(token: str) -> bool:
    """Accept both anon and service_role Supabase JWTs, and new sb_publishable_ format."""
    if _RE_SB_PUBLISHABLE.fullmatch(token):
        return True
    try:
        import jwt
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("role") in ("anon", "service_role")
    except Exception:
        return False


def _extract_credentials(content: str, source: str) -> Optional[Credentials]:
    project_ref: Optional[str] = None
    anon_key: Optional[str] = None

    # createClient pattern gives both ref and key
    m = _RE_CREATE_CLIENT.search(content)
    if m:
        project_ref = m.group(1)
        anon_key = m.group(2)

    # Tuple format: ('https://ref.supabase.co', 'eyJ...')
    if not (project_ref and anon_key):
        m = _RE_TUPLE.search(content)
        if m:
            project_ref = m.group(1)
            anon_key = m.group(2)

    # Minified call with options arg: Ps('https://ref.supabase.co', 'eyJ...', {...})
    if not (project_ref and anon_key):
        m = _RE_URL_KEY_PAIR.search(content)
        if m:
            candidate = m.group(2)
            if is_valid_supabase_key(candidate):
                project_ref = m.group(1)
                anon_key = candidate

    # Fall back to ref from URL
    if not project_ref:
        m = _RE_PROJECT_REF.search(content)
        if m:
            project_ref = m.group(1)

    # Key patterns
    if not anon_key:
        for pattern in (_RE_SUPABASE_KEY, _RE_ANON_KEY):
            m = pattern.search(content)
            if m:
                candidate = m.group(1)
                if _RE_JWT.match(candidate) or _RE_SB_PUBLISHABLE.fullmatch(candidate):
                    anon_key = candidate
                    break

    # Last resort: any JWT or sb_publishable_ key that looks like a Supabase key
    if not anon_key:
        for token in _RE_JWT.findall(content):
            if is_valid_supabase_key(token):
                anon_key = token
                break
    if not anon_key:
        for token in _RE_SB_PUBLISHABLE.findall(content):
            anon_key = token
            break

    if project_ref and anon_key:
        return Credentials(project_ref=project_ref, anon_key=anon_key, source=source)
    return None


def find_edge_functions(content: str) -> list[str]:
    return list(dict.fromkeys(_RE_EDGE_FN.findall(content)))


def find_table_names(content: str) -> list[str]:
    return list(dict.fromkeys(_RE_FROM.findall(content)))


def find_rpc_names(content: str) -> list[str]:
    return list(dict.fromkeys(_RE_RPC.findall(content)))


@dataclass
class ResourceHints:
    """Resource names referenced by client code, used when the OpenAPI spec is unavailable."""
    tables: list[str] = field(default_factory=list)
    rpcs: list[str] = field(default_factory=list)
    edge_functions: list[str] = field(default_factory=list)
    sources_scanned: int = 0

    def add(self, content: str) -> None:
        for dst, found in (
            (self.tables, find_table_names(content)),
            (self.rpcs, find_rpc_names(content)),
            (self.edge_functions, find_edge_functions(content)),
        ):
            for name in found:
                if name not in dst:
                    dst.append(name)
        self.sources_scanned += 1


_CRAWL_PATHS = [
    "/", "/login", "/signin", "/signup", "/auth", "/dashboard",
    "/app", "/admin", "/home", "/index",
]

_RE_JS_SRC = re.compile(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']')
# JS chunk references inside bundles: import("./x.js"), __vite__mapDeps(["assets/x.js"])
_RE_JS_CHUNK = re.compile(r'[\'"`]((?:\.{1,2}/|/)?[A-Za-z0-9_./-]+\.js)[\'"`]')
_MAX_JS_FILES = 300


def _collect_js_urls(html: str, base: str) -> list[str]:
    """Extract all JS URLs from HTML (script src tags and inline references)."""
    seen: set[str] = set()
    result: list[str] = []
    for src in _RE_JS_SRC.findall(html):
        if not src.startswith("http"):
            src = base + ("" if src.startswith("/") else "/") + src
        if src not in seen:
            seen.add(src)
            result.append(src)
    return result


def _collect_chunk_urls(js: str, js_url: str, base: str) -> list[str]:
    """Extract lazily-loaded chunk URLs referenced from inside a JS bundle."""
    result: list[str] = []
    for ref in _RE_JS_CHUNK.findall(js):
        if ref.startswith(("./", "../")):
            result.append(urljoin(js_url, ref))
        else:
            result.append(urljoin(base + "/", ref))
    return [u for u in result if urlparse(u).netloc == urlparse(base).netloc]


def _iter_sources(url: str, follow_chunks: bool = False) -> Iterator[tuple[str, str]]:
    """Yield (source_url, text) for the target page, common sub-paths, and their JS files."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    seen_js: set[str] = set()
    all_js: list[str] = []

    # Crawl the target URL plus common sub-paths to collect all JS chunk URLs
    crawl_targets = [url]
    # Add sub-paths only for root-level URLs (not deep links)
    if parsed.path in ("", "/"):
        crawl_targets += [base + p for p in _CRAWL_PATHS if base + p != url]

    for crawl_url in crawl_targets:
        try:
            resp = requests.get(crawl_url, timeout=10)
        except Exception as e:
            print(f"  [WARN] Failed to fetch {crawl_url}: {e}")
            continue

        yield crawl_url, resp.text

        # Collect JS URLs from this page
        for js_url in _collect_js_urls(resp.text, base):
            if js_url not in seen_js:
                seen_js.add(js_url)
                all_js.append(js_url)

    # Scan all collected JS files (list grows as chunks are discovered)
    i = 0
    while i < len(all_js) and i < _MAX_JS_FILES:
        js_url = all_js[i]
        i += 1
        try:
            js_resp = requests.get(js_url, timeout=10)
        except Exception:
            continue
        if js_resp.status_code != 200:
            continue
        yield js_url, js_resp.text
        if follow_chunks:
            for chunk in _collect_chunk_urls(js_resp.text, js_url, base):
                if chunk not in seen_js:
                    seen_js.add(chunk)
                    all_js.append(chunk)


def from_url(url: str) -> Optional[Credentials]:
    for source, text in _iter_sources(url, follow_chunks=True):
        creds = _extract_credentials(text, source=source)
        if creds:
            return creds
    return None


def collect_hints(target: str) -> ResourceHints:
    """Scan a URL (full crawl incl. lazy chunks) or local file for referenced resource names."""
    hints = ResourceHints()
    if target.startswith(("http://", "https://")):
        for _, text in _iter_sources(target, follow_chunks=True):
            hints.add(text)
    elif Path(target).is_file():
        hints.add(Path(target).read_text(errors="replace"))
    return hints


def from_html_file(path: str) -> Optional[Credentials]:
    content = Path(path).read_text(errors="replace")
    return _extract_credentials(content, source=path)


def from_js_file(path: str) -> Optional[Credentials]:
    content = Path(path).read_text(errors="replace")
    return _extract_credentials(content, source=path)


def from_har_file(path: str) -> Optional[Credentials]:
    try:
        har = json.loads(Path(path).read_text())
    except Exception as e:
        print(f"  [WARN] Failed to parse HAR file: {e}")
        return None

    entries = har.get("log", {}).get("entries", [])
    for entry in entries:
        req = entry.get("request", {})
        # Check URL
        url_str = req.get("url", "")
        creds = _extract_credentials(url_str, source=path)
        if creds:
            return creds
        # Check request headers
        for header in req.get("headers", []):
            val = header.get("value", "")
            creds = _extract_credentials(val, source=path)
            if creds:
                return creds
        # Check post data
        post_data = req.get("postData", {}).get("text", "")
        if post_data:
            creds = _extract_credentials(post_data, source=path)
            if creds:
                return creds
        # Check response body
        resp_text = entry.get("response", {}).get("content", {}).get("text", "")
        if resp_text:
            creds = _extract_credentials(resp_text, source=path)
            if creds:
                return creds
    return None
