#!/usr/bin/env python3
"""Take screenshots of the FMS Camera System for the user guide."""
import os, sys, time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL = "http://localhost"
OUT_DIR  = Path(__file__).parent / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

USERNAME = os.environ.get("GUIDE_USER", "admin")
PASSWORD = os.environ.get("GUIDE_PASS", "")

def shot(page, name, selector=None, full=False):
    path = str(OUT_DIR / f"{name}.png")
    if selector:
        page.locator(selector).first.screenshot(path=path)
    else:
        page.screenshot(path=path, full_page=full)
    print(f"  ✓ {name}.png")

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx  = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()

        # ── 1. Login page ─────────────────────────────────────────────────────
        print("Login page…")
        page.goto(f"{BASE_URL}/login")
        page.wait_for_load_state("networkidle")
        shot(page, "01_login")

        # ── 2. Sign in ────────────────────────────────────────────────────────
        page.fill("input[name=username]", USERNAME)
        page.fill("input[name=password]", PASSWORD)
        page.click("button[type=submit]")
        page.wait_for_url(f"{BASE_URL}/", timeout=10000)
        page.wait_for_timeout(3000)   # let cameras load

        # ── 3. Dashboard overview ─────────────────────────────────────────────
        print("Dashboard…")
        shot(page, "02_dashboard", full=False)

        # ── 4. Camera card close-up (first visible card) ──────────────────────
        print("Camera card…")
        card = page.locator(".camera-card").first
        if card.count():
            shot(page, "03_camera_card", ".camera-card")

        # ── 5. Checkbox hover state (inject checked state) ────────────────────
        print("Selection checkbox…")
        page.evaluate("""
            const cb = document.querySelector('.cam-select-cb');
            if (cb) { cb.checked = true; cb.style.opacity = '1';
                      cb.dispatchEvent(new Event('change')); }
        """)
        page.wait_for_timeout(400)
        shot(page, "04_camera_selected", ".camera-card")

        # ── 6. Multiple cameras selected + sel-bar ────────────────────────────
        print("Selection bar…")
        page.evaluate("""
            document.querySelectorAll('.cam-select-cb').forEach((cb, i) => {
                if (i < 4) { cb.checked = true; cb.style.opacity = '1';
                              cb.dispatchEvent(new Event('change')); }
            });
        """)
        page.wait_for_timeout(500)
        shot(page, "05_selection_bar")

        # ── 7. Category "Watch" button (annotate the header) ─────────────────
        print("Watch button…")
        # Scroll to top first
        page.evaluate("window.scrollTo(0,0)")
        shot(page, "06_watch_buttons")

        # ── 8. Grid view (open via Watch button on first category) ────────────
        print("Grid view…")
        watch_btn = page.locator(".btn-watch-grid").first
        if watch_btn.count():
            watch_btn.click()
            page.wait_for_timeout(3000)
            shot(page, "07_grid_view")
            # Close grid
            page.keyboard.press("Escape")
            page.wait_for_timeout(500)

        # ── 9. Live view (click first Live button) ────────────────────────────
        print("Live view…")
        live_btn = page.locator("button.btn-sm.primary", has_text="Live").first
        if live_btn.count():
            live_btn.click()
            page.wait_for_timeout(3000)
            shot(page, "08_live_view")
            page.keyboard.press("Escape")
            page.wait_for_timeout(500)

        # ── 10. Recordings page ───────────────────────────────────────────────
        print("Recordings…")
        page.goto(f"{BASE_URL}/recordings")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(2000)
        shot(page, "09_recordings")

        browser.close()
    print("\nAll screenshots saved to", OUT_DIR)

if __name__ == "__main__":
    if not PASSWORD:
        print("Usage: GUIDE_USER=admin GUIDE_PASS=yourpass python3 take_screenshots.py")
        sys.exit(1)
    run()
