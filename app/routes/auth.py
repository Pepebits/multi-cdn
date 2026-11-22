"""Sign-in (password, TOTP, enrolment), sign-out and the account settings tab."""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from markupsafe import Markup

from .. import event_codes
from ..auth import totp_uri
from ..i18n import tn, tr
from .common import (
    LOCK_MSG,
    RECOVERY_LOW,
    _auth_page,
    _card,
    _client_ip,
    _safe_next,
    _settings_page,
    _state,
    _totp_attempt,
    _with_session,
)

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    s = _state(request)
    if request.state.session:
        return RedirectResponse(_safe_next(request.query_params.get("next")), status_code=303)
    return _auth_page(request, "login.html", has_users=s.auth.has_users(), error=request.query_params.get("error"))


@router.post("/login")
async def login_post(request: Request, username: str = Form(""), password: str = Form(""), next: str = Form("/")):
    s = _state(request)
    keys = (f"u:{username.strip().lower()}", f"ip:{_client_ip(request)}")
    if s.auth.locked(*keys):
        return _auth_page(request, "login.html", has_users=True, error=tr(LOCK_MSG), username=username)
    user = s.auth.check_password(username, password)
    if user is None:
        s.auth.register_failure(*keys)
        s.events.add(actor="auto", kind="auth", summary=tn('Wrong password for "{user}" from {ip}', user=username.strip()[:40], ip=_client_ip(request)))
        if s.auth.locked(*keys):
            s.events.add(actor="auto", kind="auth",
                         code=event_codes.LOGIN_LOCKED,
                         summary=tn('Access blocked after failed attempts ("{user}" from {ip})',
                                    user=username.strip()[:40], ip=_client_ip(request)))
        return _auth_page(request, "login.html", has_users=True, error=tr("Incorrect username or password."), username=username)
    stage = "pending" if user.totp_enabled else "enroll"
    token = s.auth.create_session(user.id, stage, _client_ip(request), request.headers.get("user-agent"))
    target = "/login/codigo" if stage == "pending" else "/login/alta"
    return _with_session(RedirectResponse(f"{target}?{urlencode({'next': _safe_next(next)})}", status_code=303), request, token)


def _finish_login(request: Request, user_id: int, username: str, next_url: str) -> Response:
    s = _state(request)
    pending = request.state.pending
    if pending:
        s.auth.delete_session(pending.id_hash)  # nuevo identificador tras autenticar
    token = s.auth.create_session(user_id, "full", _client_ip(request), request.headers.get("user-agent"))
    s.auth.register_success(f"u:{username}", f"ip:{_client_ip(request)}")
    s.events.add(actor=username, kind="auth", summary=tn("Signed in from {ip}", ip=_client_ip(request)))
    return _with_session(RedirectResponse(_safe_next(next_url), status_code=303), request, token)


@router.get("/login/codigo", response_class=HTMLResponse)
async def login_codigo(request: Request):
    pending = request.state.pending
    if not pending or pending.stage != "pending":
        return RedirectResponse("/login", status_code=303)
    return _auth_page(request, "login_codigo.html", username=pending.user.username)


@router.post("/login/codigo")
async def login_codigo_post(request: Request, code: str = Form(""), next: str = Form("/")):
    s = _state(request)
    pending = request.state.pending
    if not pending or pending.stage != "pending":
        return RedirectResponse(f"/login?{urlencode({'error': tr('The session has expired')})}", status_code=303)
    user = pending.user
    keys = (f"u:{user.username}", f"ip:{_client_ip(request)}")
    if s.auth.locked(*keys):
        s.auth.delete_session(pending.id_hash)
        return _with_session(RedirectResponse(f"/login?{urlencode({'error': tr(LOCK_MSG)})}", status_code=303), request, None)
    code = code.strip()
    used_recovery = False
    ok = s.auth.check_totp(user.id, code)
    if not ok and "-" in code:
        ok = used_recovery = s.auth.use_recovery_code(user.id, code)
    if not ok:
        s.auth.register_failure(*keys)
        s.events.add(actor="auto", kind="auth", summary=tn("Wrong code for {user} from {ip}", user=user.username, ip=_client_ip(request)))
        if s.auth.locked(*keys):
            s.events.add(actor="auto", kind="auth",
                         code=event_codes.LOGIN_LOCKED,
                         summary=tn("Access blocked after failed attempts ({user} from {ip})",
                                    user=user.username, ip=_client_ip(request)))
        return _auth_page(request, "login_codigo.html", username=user.username, error=tr("Wrong or already used code."))
    if used_recovery:
        s.events.add(actor=user.username, kind="auth",
                     summary=tn("Signed in with a recovery code ({n} left)", n=s.auth.recovery_left(user.id)))
    return _finish_login(request, user.id, user.username, next)


@router.get("/login/alta", response_class=HTMLResponse)
async def login_alta(request: Request):
    import segno
    s = _state(request)
    pending = request.state.pending
    if not pending or pending.stage != "enroll":
        return RedirectResponse("/login", status_code=303)
    secret = s.auth.totp_secret(pending.user.id) or s.auth.start_totp_enrollment(pending.user.id)
    uri = totp_uri(secret, pending.user.username)
    qr = segno.make(uri, error="m").svg_inline(scale=5, dark="#1c1b1b", light="#ffffff")
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return _auth_page(request, "login_alta.html", qr=Markup(qr), secret=grouped, username=pending.user.username,
                      error=request.query_params.get("error"))


@router.post("/login/alta")
async def login_alta_post(request: Request, code: str = Form(""), next: str = Form("/")):
    s = _state(request)
    pending = request.state.pending
    if not pending or pending.stage != "enroll":
        return RedirectResponse("/login", status_code=303)
    user = pending.user
    passed = _totp_attempt(request, pending, lambda: s.auth.check_totp(user.id, code))
    if isinstance(passed, Response):
        return passed
    if not passed:
        return RedirectResponse(f"/login/alta?{urlencode({'error': tr('Wrong code: check the clock of your phone'), 'next': _safe_next(next)})}",
                                status_code=303)
    s.auth.enable_totp(user.id)
    codes = s.auth.new_recovery_codes(user.id)
    s.events.add(actor=user.username, kind="auth", summary=tn("TOTP enabled"))
    s.auth.delete_session(pending.id_hash)
    token = s.auth.create_session(user.id, "full", _client_ip(request), request.headers.get("user-agent"))
    s.events.add(actor=user.username, kind="auth", summary=tn("Signed in from {ip}", ip=_client_ip(request)))
    response = _auth_page(request, "login_recuperacion.html", codes=codes, next=_safe_next(next))
    return _with_session(response, request, token)


@router.post("/logout")
async def logout(request: Request):
    s = _state(request)
    if request.state.session:
        s.auth.delete_session(request.state.session.id_hash)
        s.events.add(actor=request.state.session.user.username, kind="auth", summary=tn("Signed out"))
    return _with_session(RedirectResponse("/login", status_code=303), request, None)


@router.get("/ajustes/cuenta", response_class=HTMLResponse)
async def ajustes_cuenta(request: Request):
    s = _state(request)
    me = request.state.session
    return _settings_page(request, "cuenta", "ajustes_cuenta.html", sessions=s.auth.list_sessions(me.user.id),
                          current_hash=me.id_hash, recovery_left=s.auth.recovery_left(me.user.id),
                          recovery_low=RECOVERY_LOW)


@router.post("/ajustes/cuenta/password")
async def cuenta_password(request: Request, current: str = Form(""), code: str = Form(""), new: str = Form(""),
                          new2: str = Form("")):
    s = _state(request)
    me = request.state.session
    url = request.url_for("ajustes_cuenta")
    passed = _totp_attempt(
        request, me,
        lambda: s.auth.check_password(me.user.username, current) is not None and s.auth.check_totp(me.user.id, code),
        failure=tn("Password change rejected: wrong credentials"), actor=me.user.username)
    if isinstance(passed, Response):
        return passed
    if not passed:
        return _card(url, "password", error=tr("The current password or the code is not correct"))
    if new != new2:
        return _card(url, "password", error=tr("The new passwords do not match"))
    try:
        s.auth.set_password(me.user.id, new)
    except ValueError as exc:
        return _card(url, "password", error=str(exc))
    closed = s.auth.close_sessions(me.user.id, except_hash=me.id_hash)
    s.events.add(actor=me.user.username, kind="auth", summary=tn("Password changed; {n} sessions closed", n=closed))
    if closed == 0:
        msg = tr("Password changed. You had no other sessions open.")
    elif closed == 1:
        msg = tr("Password changed. Your other session has been closed.")
    else:
        msg = tr("Password changed. Your other {n} sessions have been closed.", n=closed)
    return _card(url, "password", ok=msg)


@router.post("/ajustes/cuenta/recuperacion")
async def cuenta_recuperacion(request: Request, code: str = Form("")):
    s = _state(request)
    me = request.state.session
    passed = _totp_attempt(request, me, lambda: s.auth.check_totp(me.user.id, code))
    if isinstance(passed, Response):
        return passed
    if not passed:
        return _card(request.url_for("ajustes_cuenta"), "recuperacion", error=tr("Wrong TOTP code"))
    codes = s.auth.new_recovery_codes(me.user.id)
    s.events.add(actor=me.user.username, kind="auth", summary=tn("Recovery codes regenerated"))
    return _auth_page(request, "login_recuperacion.html", codes=codes, next="/ajustes/cuenta")


@router.post("/ajustes/cuenta/sesiones/{id_hash}/cerrar")
async def cuenta_cerrar_sesion(request: Request, id_hash: str):
    s = _state(request)
    me = request.state.session
    if any(x.id_hash == id_hash for x in s.auth.list_sessions(me.user.id)):
        s.auth.delete_session(id_hash)
        s.events.add(actor=me.user.username, kind="auth", summary=tn("Session closed from My account"))
    if id_hash == me.id_hash:
        return _with_session(RedirectResponse("/login", status_code=303), request, None)
    return _card(request.url_for("ajustes_cuenta"), "sesiones", ok=tr("Session closed"))
