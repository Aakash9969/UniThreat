"""Guard the dashboard's JavaScript against syntax errors.

The dashboard is pure client-side JS with no build step, so a single syntax
error silently kills the whole UI (buttons dead, nothing renders) while the
server keeps reporting healthy — exactly the failure mode that once shipped.
This module parses every static JS file with Node (skipped when Node is
absent), requires a cache-busted script tag, and bans literal named HTML
entities from JS source (tooling has mangled them into raw characters,
breaking the file).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_STATIC = Path(__file__).resolve().parents[1] / "src" / "server" / "static"


def test_dashboard_js_parses():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js not available for JS syntax validation")
    js_files = sorted(_STATIC.glob("*.js"))
    assert js_files, "no dashboard JS files found"
    for js in js_files:
        result = subprocess.run(
            [node, "--check", str(js)],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, (
            f"{js.name} has a syntax error (the dashboard would be dead):\n"
            f"{result.stderr}"
        )


def test_html_references_js_with_cache_buster():
    """The script tag must carry a version query so browser caches can't
    serve a stale/broken app.js after a fix."""
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    assert 'src="/static/app.js?v=' in html, (
        "index.html must reference app.js with a ?v= cache-buster"
    )


def test_no_named_html_entities_in_js():
    """Named HTML entities in JS source have been mangled by tooling before
    (unescaped into raw characters, producing a syntax error that killed
    the whole dashboard). Numeric entities built via charCodeAt are immune,
    so literal named entities are banned outright."""
    entity_pattern = re.compile("&[a-zA-Z]+;")  # matches e.g. amp-ersand
    for js in sorted(_STATIC.glob("*.js")):
        text = js.read_text(encoding="utf-8")
        match = entity_pattern.search(text)
        assert match is None, (
            f"{js.name} contains the literal named entity {match.group()!r} — "
            "build HTML escapes with charCodeAt(0) instead; named entities "
            "have been mangled into raw characters before, breaking the file"
        )
