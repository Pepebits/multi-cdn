"""Automatic accessibility check (axe-core) of every page, at desktop and phone size: no problem of
moderate impact or above (only "minor" ones would pass)."""

import pytest
from axe_playwright_python.sync_playwright import Axe

from .test_panel_browser import PAGES

AXE = Axe()


@pytest.mark.parametrize("path", PAGES + ["/login"])
def test_no_serious_accessibility_problems(signed_in, path):
    page = signed_in
    page.goto(page.base + path)
    # preload off: axe would fetch the Google Fonts CSS, which the panel's CSP (rightly) blocks.
    results = AXE.run(page, options={"resultTypes": ["violations"], "preload": False})
    problems = [f"{v['id']} ({v['impact']}): {v['help']} — {len(v['nodes'])}× e.g. {v['nodes'][0]['target']}"
                for v in results.response["violations"] if v["impact"] in ("moderate", "serious", "critical")]
    assert not problems, "\n".join(problems)
