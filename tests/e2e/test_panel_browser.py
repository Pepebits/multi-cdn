"""The panel in a real browser, at desktop and phone size."""

import re

import pytest
from playwright.sync_api import expect

from .conftest import DESKTOP, PASSWORD, PHONE

PAGES = ["/", "/dominios", "/dominios/example.com", "/historial", "/estadisticas", "/ajustes/cuentas",
         "/ajustes/servidores", "/ajustes/notificaciones", "/ajustes/cambio", "/ajustes/sistema", "/ajustes/cuenta"]


@pytest.mark.parametrize("path", PAGES)
def test_every_page_fits_the_screen_without_errors(signed_in, path):
    page = signed_in
    response = page.goto(page.base + path)
    assert response.status == 200
    # No horizontal scroll of the whole page (tables may scroll inside their own frame).
    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    assert overflow <= 1, f"{path} is {overflow}px wider than the screen"
    expect(page.locator("h1").first).to_be_visible()


def test_phone_shows_the_bottom_navigation(signed_in):
    page = signed_in
    page.goto(page.base + "/")
    nav = page.locator(".sidebar")
    box = nav.bounding_box()
    if page.form_factor == "phone":
        assert box["y"] + box["height"] >= PHONE["height"] - 2 and box["width"] >= PHONE["width"] - 2
        expect(page.locator(".nav a", has_text="Dominios")).to_be_visible()
    else:
        assert box["x"] == 0 and box["height"] >= DESKTOP["height"] - 2


def test_confirmation_dialog_focuses_cancel_and_escape_closes_it(signed_in):
    page = signed_in
    page.goto(page.base + "/dominios/example.com")
    page.click("[data-open='quitar-host-2']")
    dialog = page.locator("dialog#quitar-host-2")
    expect(dialog).to_be_visible()
    assert page.evaluate("document.activeElement.textContent.trim()") == "Cancelar"
    page.keyboard.press("Enter")  # Enter on the focused Cancel: nothing removed
    expect(dialog).to_be_hidden()
    expect(page.locator("tbody th", has_text="www.example.com")).to_be_visible()


def test_typed_confirmation_focuses_its_field_and_unlocks_the_button(signed_in):
    page = signed_in
    page.goto(page.base + "/dominios/example.com")
    page.click("button[data-open^='del-']")
    field = page.locator("dialog[open] input[data-expected]")
    expect(field).to_be_focused()
    submit = page.locator("dialog[open] [data-submit]")
    expect(submit).to_be_disabled()
    field.fill("Example.com")  # a phone keyboard may capitalise the first letter
    expect(submit).to_be_enabled()
    page.keyboard.press("Escape")
    expect(page.locator("dialog[open]")).to_have_count(0)


def test_show_password_toggles_the_label_and_hides_again_on_submit(signed_in):
    page = signed_in
    page.goto(page.base + "/ajustes/cuenta")
    field, toggle = page.locator("#current"), page.locator("[data-reveal='current']")
    field.fill("texto")
    toggle.click()
    expect(field).to_have_attribute("type", "text")
    expect(toggle).to_have_text("Ocultar")
    toggle.click()
    expect(field).to_have_attribute("type", "password")
    expect(toggle).to_have_text("Mostrar")


def test_theme_choice_applies_and_survives_a_reload(signed_in):
    page = signed_in
    page.goto(page.base + "/")
    page.click("[data-theme-choice='light']")
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    page.reload()
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    page.click("[data-theme-choice='dark']")
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") != bg
    page.click("[data-theme-choice='auto']")
    assert page.evaluate("document.documentElement.dataset.theme") is None


def test_sign_in_with_a_recovery_code_on_a_phone(browser, panel):
    """The recovery code has letters: its field must not open a numeric keypad."""
    context = browser.new_context(viewport=PHONE, is_mobile=True, has_touch=True, locale="es-ES")
    page = context.new_page()
    page.goto(panel["url"] + "/login")
    page.fill("#username", "prueba")
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url("**/login/codigo**")
    expect(page.locator("#code")).to_have_attribute("inputmode", "numeric")
    page.click("summary")
    recovery = page.locator("#recovery")
    expect(recovery).to_be_visible()
    assert recovery.get_attribute("inputmode") is None
    recovery.fill(panel["codes"][0])
    page.locator("details button[type=submit]").click()
    page.wait_for_url(panel["url"] + "/")
    expect(page.locator("h1").first).to_have_text(re.compile("Resumen"))
    context.close()
