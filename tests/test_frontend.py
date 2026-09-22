"""Static checks on the front end.

There is no browser in this test environment, so these catch the class of bug
that has no server-side symptom at all: the page serves 200, the API is
healthy, and the interface is dead because a script that defines a global was
never loaded. That exact bug shipped on the login page — api.js defines the
API global, login.js calls API.post(), and login.html loaded only the second
one. A strict CSP means there is no inline fallback, so it fails silently with
"API is not defined" in a console the user has to open to see.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
JS = ROOT / "static" / "js"

# Global -> the file that defines it.
PROVIDERS = {"API": "api.js", "R": "render.js"}


def scripts_of(page: Path):
    """Script filenames a page loads, in document order."""
    return re.findall(r'<script src="/static/js/([^"]+)"></script>', page.read_text(encoding="utf-8"))


def globals_used(script: Path):
    """Which shared globals a script actually calls."""
    src = script.read_text(encoding="utf-8")
    used = set()
    for name in PROVIDERS:
        if re.search(r"(?<![\w.])" + name + r"\s*\.", src):
            used.add(name)
    return used


PAGES = sorted(TEMPLATES.glob("*.html"))


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_every_global_a_page_uses_is_loaded_by_that_page(page):
    loaded = scripts_of(page)
    for script_name in loaded:
        script = JS / script_name
        if not script.exists():
            pytest.fail(f"{page.name} loads {script_name}, which does not exist")
        for name in globals_used(script):
            provider = PROVIDERS[name]
            assert provider in loaded, (
                f"{page.name} loads {script_name}, which uses the '{name}' global, "
                f"but never loads {provider} that defines it"
            )


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_providers_load_before_their_consumers(page):
    """Order matters: these are classic scripts, not modules."""
    loaded = scripts_of(page)
    for index, script_name in enumerate(loaded):
        script = JS / script_name
        if not script.exists():
            continue
        for name in globals_used(script):
            provider = PROVIDERS[name]
            if provider in loaded:
                assert loaded.index(provider) < index, (
                    f"{page.name}: {provider} must load before {script_name}"
                )


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_no_inline_script_or_style(page):
    """The CSP has no 'unsafe-inline', so anything inline is dead code."""
    src = page.read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>", src), \
        f"{page.name} has an inline <script>, which the CSP blocks"
    assert not re.search(r'\sstyle="', src), \
        f"{page.name} has an inline style attribute, which the CSP blocks"
    assert not re.search(r"<style[\s>]", src), \
        f"{page.name} has an inline <style> block, which the CSP blocks"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_every_element_id_referenced_by_js_exists(page):
    """getElementById targets must be present in some template."""
    html = "\n".join(p.read_text(encoding="utf-8") for p in PAGES)
    available = set(re.findall(r'id="([^"]+)"', html))
    for script_name in scripts_of(page):
        script = JS / script_name
        if not script.exists():
            continue
        for element_id in re.findall(
                r"""getElementById\(['"]([^'"]+)['"]\)""", script.read_text(encoding="utf-8")):
            assert element_id in available, (
                f"{script_name} looks for #{element_id}, which no template defines"
            )


def test_stylesheet_is_linked_and_present():
    for page in PAGES:
        assert '<link rel="stylesheet" href="/static/css/style.css">' in page.read_text(encoding="utf-8"), \
            f"{page.name} does not link the stylesheet"
    assert (ROOT / "static" / "css" / "style.css").exists()


def test_all_javascript_files_are_reachable_from_some_page():
    """A script nothing loads is either dead code or a missing include."""
    loaded = {s for page in PAGES for s in scripts_of(page)}
    on_disk = {p.name for p in JS.glob("*.js")}
    orphans = on_disk - loaded
    assert not orphans, f"these scripts are never loaded by any page: {sorted(orphans)}"
