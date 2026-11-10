"""OAuth 2.1 authorization server for AI clients, backed by the person's Exchange login.

Flow: the AI client registers itself (dynamic client registration), sends the
person to `/authorize`, and we redirect them to our own `/login` page. There
they enter their Exchange username and password once. We verify the password
against EWS, store it encrypted, mint an authorization code, and send the
browser back to the client's redirect URI. The client exchanges the code for
an access token (1 hour) and a refresh token (30 days). The AI vendor only
ever holds our tokens, never the Exchange password.
"""

from __future__ import annotations

import html
import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Any

import anyio
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .accounts import StoreAccounts
from .backend import AuthFailed, BackendUnavailable
from .store import Store

log = logging.getLogger(__name__)

SCOPE = "mail.read"
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 300


class RateLimiter:
    """Small fixed-window limiter keyed by string (client IP, e-mail)."""

    def __init__(self, limit: int = 5, window: float = 900.0) -> None:
        self._limit = limit
        self._window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and q[0] < now - self._window:
                q.popleft()
            if len(q) >= self._limit:
                return False
            q.append(now)
            return True


class ExchangeLoginProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, store: Store, accounts: StoreAccounts, base_url: str) -> None:
        self._store = store
        self._accounts = accounts
        self._base = base_url.rstrip("/")
        self._limiter = RateLimiter()
        self._page_limiter = RateLimiter(limit=10)  # /mailboxes: password check is local, allow a few more

    # -- clients -------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self._store.get_client(client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        assert client_info.client_id is not None
        self._store.save_client(client_info.client_id, client_info.model_dump(mode="json", exclude_none=True))

    # -- authorize -----------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        assert client.client_id is not None
        txn = secrets.token_urlsafe(32)
        self._store.save_txn(txn, client.client_id, params.model_dump(mode="json"))
        return f"{self._base}/login?txn={txn}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        data = self._store.get_code(authorization_code)
        if not data or data.get("client_id") != client.client_id:
            return None
        return AuthorizationCode.model_validate(data)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._store.delete_code(authorization_code.code)
        if not authorization_code.subject:
            raise TokenError("invalid_grant", "Authorization code has no subject")
        return self._issue(
            client_id=authorization_code.client_id,
            sub=authorization_code.subject,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
        )

    # -- tokens --------------------------------------------------------------

    def _issue(self, *, client_id: str, sub: str, scopes: list[str], resource: str | None) -> OAuthToken:
        pair_id = secrets.token_urlsafe(16)
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = time.time()
        self._store.save_token(
            access,
            kind="access",
            pair_id=pair_id,
            client_id=client_id,
            sub=sub,
            scopes=scopes,
            resource=resource,
            expires_at=now + ACCESS_TTL,
        )
        self._store.save_token(
            refresh,
            kind="refresh",
            pair_id=pair_id,
            client_id=client_id,
            sub=sub,
            scopes=scopes,
            resource=resource,
            expires_at=now + REFRESH_TTL,
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TTL,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        t = self._store.get_token(refresh_token, "refresh")
        if not t or t.client_id != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=t.client_id,
            scopes=t.scopes,
            expires_at=int(t.expires_at) if t.expires_at else None,
            resource=t.resource,
            subject=t.sub,
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        t = self._store.get_token(refresh_token.token, "refresh")
        if not t:
            raise TokenError("invalid_grant", "Refresh token is not valid")
        if any(s not in t.scopes for s in scopes):
            raise TokenError("invalid_scope", "Requested scope exceeds the original grant")
        self._store.delete_token_pair(t.pair_id)  # rotation: old access + refresh both die
        return self._issue(client_id=t.client_id, sub=t.sub, scopes=scopes or t.scopes, resource=t.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        t = self._store.get_token(token, "access")
        if not t:
            return None
        user = self._store.get_user(t.sub)
        if user is None:
            return None  # the person removed their login; their tokens die with it
        return AccessToken(
            token=token,
            client_id=t.client_id,
            scopes=t.scopes,
            expires_at=int(t.expires_at) if t.expires_at else None,
            resource=t.resource,
            subject=t.sub,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        kind = "refresh" if isinstance(token, RefreshToken) else "access"
        t = self._store.get_token(token.token, kind)
        if t:
            self._store.delete_token_pair(t.pair_id)

    # -- login pages (registered as custom routes, no bearer auth) -----------

    async def login_get(self, request: Request) -> Response:
        txn = request.query_params.get("txn", "")
        if not txn or not self._store.peek_txn(txn):
            return HTMLResponse(_page("This sign-in link has expired. Start again from your AI app."), 400)
        return HTMLResponse(_login_form(action="/login", txn=txn))

    async def login_post(self, request: Request) -> Response:
        form = await request.form()
        txn = str(form.get("txn", ""))
        pending = self._store.peek_txn(txn)
        if not pending:
            return HTMLResponse(_page("This sign-in link has expired. Start again from your AI app."), 400)
        client_id, params = pending
        result = await self._try_login(request, form)
        if isinstance(result, Response):
            return result
        user_sub = result
        self._store.pop_txn(txn)
        code = secrets.token_urlsafe(32)
        self._store.save_code(
            code,
            {
                "code": code,
                "client_id": client_id,
                "scopes": params.get("scopes") or [SCOPE],
                "expires_at": time.time() + CODE_TTL,
                "code_challenge": params["code_challenge"],
                "redirect_uri": params["redirect_uri"],
                "redirect_uri_provided_explicitly": params["redirect_uri_provided_explicitly"],
                "resource": params.get("resource"),
                "subject": user_sub,
            },
            expires_at=time.time() + CODE_TTL,
        )
        target = construct_redirect_uri(params["redirect_uri"], code=code, state=params.get("state"))
        return RedirectResponse(target, status_code=302)

    async def relogin_get(self, request: Request) -> Response:
        return HTMLResponse(_login_form(action="/relogin", txn=None))

    async def relogin_post(self, request: Request) -> Response:
        form = await request.form()
        result = await self._try_login(request, form)
        if isinstance(result, Response):
            return result
        return HTMLResponse(_page("Password updated. Your AI app will work again on its next request."))

    # -- additional mailboxes page ------------------------------------------

    async def mailboxes_get(self, request: Request) -> Response:
        return HTMLResponse(_mailboxes_form())

    async def mailboxes_post(self, request: Request) -> Response:
        """Add, update or remove an additional mailbox.

        The person proves who they are with their main login, which is compared with the
        stored password (no call to Exchange, so a typo cannot lock the directory account).
        The additional mailbox's own password is verified against Exchange once before storing.
        """
        form = await request.form()
        owner_email = str(form.get("owner_email", "")).strip()
        owner_password = str(form.get("owner_password", ""))
        action = str(form.get("action", "add"))
        email = str(form.get("email", "")).strip()
        username = str(form.get("username", "")).strip() or email
        password = str(form.get("password", ""))
        ip = request.client.host if request.client else "?"
        if not owner_email or not owner_password or not email:
            return HTMLResponse(
                _page("Your main e-mail, its password and the mailbox address are required.", back=True), 400
            )
        if not self._page_limiter.allow(f"ip:{ip}") or not self._page_limiter.allow(
            f"owner:{owner_email.lower()}"
        ):
            log.warning("mailboxes page rate limit hit for ip=%s", ip)
            return HTMLResponse(_page("Too many attempts. Wait 15 minutes and try again."), 429)
        owner_sub = self._store.sub_for_email(owner_email)
        owner = self._store.get_user(owner_sub)
        if owner is None or not self._store.check_password(owner_sub, owner_password):
            log.info("mailboxes page: main login not matched for ip=%s", ip)
            return HTMLResponse(
                _page(
                    "That main e-mail and password do not match a connected account. "
                    "If you changed your password, update it at /relogin first.",
                    back=True,
                ),
                401,
            )
        if action == "remove":
            removed = self._accounts.remove_mailbox(owner_sub, email)
            log.info("additional mailbox %s for sub=%s", "removed" if removed else "not found", owner_sub)
            msg = (
                "Mailbox removed and its stored password deleted."
                if removed
                else "That mailbox was not connected."
            )
            return HTMLResponse(_page(msg))
        if not password:
            return HTMLResponse(_page("The mailbox password is required.", back=True), 400)
        if not self._limiter.allow(f"email:{email.lower()}"):
            return HTMLResponse(_page("Too many attempts. Wait 15 minutes and try again."), 429)
        try:
            await anyio.to_thread.run_sync(self._accounts.add_mailbox, owner_sub, email, username, password)
        except AuthFailed:
            log.info("additional mailbox rejected by Exchange for sub=%s", owner_sub)
            return HTMLResponse(
                _page(
                    "Exchange did not accept that mailbox login. Check the username and password.", back=True
                ),
                401,
            )
        except BackendUnavailable as exc:
            log.warning("mailboxes page could not reach Exchange: %s", exc)
            return HTMLResponse(
                _page("The mail server could not be reached. Try again in a few minutes."), 502
            )
        except ValueError as exc:
            return HTMLResponse(_page(str(exc), back=True), 400)
        log.info("additional mailbox saved for sub=%s", owner_sub)
        return HTMLResponse(
            _page("Mailbox connected. Your AI can now read it; ask it to list your mailboxes.")
        )

    async def _try_login(self, request: Request, form: Any) -> str | Response:
        email = str(form.get("email", "")).strip()
        username = str(form.get("username", "")).strip() or email
        password = str(form.get("password", ""))
        ip = request.client.host if request.client else "?"
        if not email or not password:
            return HTMLResponse(_page("E-mail and password are both required.", back=True), 400)
        if not self._limiter.allow(f"ip:{ip}") or not self._limiter.allow(f"email:{email.lower()}"):
            log.warning("login rate limit hit for ip=%s", ip)
            return HTMLResponse(_page("Too many attempts. Wait 15 minutes and try again."), 429)
        try:
            user = await anyio.to_thread.run_sync(self._accounts.login, email, username, password)
        except AuthFailed:
            log.info("login rejected by Exchange for ip=%s", ip)
            return HTMLResponse(
                _page("Exchange did not accept that login. Check the username and password.", back=True), 401
            )
        except BackendUnavailable as exc:
            log.warning("login could not reach Exchange: %s", exc)
            return HTMLResponse(
                _page("The mail server could not be reached. Try again in a few minutes."), 502
            )
        log.info("login ok for sub=%s", user.sub)
        return user.sub


# -- HTML ---------------------------------------------------------------------

_STYLE = """
body{font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#222}
label{display:block;margin:1rem 0 .25rem}input,select{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}
button{margin-top:1.25rem;padding:.6rem 1.2rem;font-size:1rem}small{color:#666}
.note{background:#f6f6f6;padding:.75rem;border-radius:.4rem;margin-top:1.5rem;font-size:.9rem}
"""


def _page(message: str, *, back: bool = False) -> str:
    extra = '<p><a href="javascript:history.back()">Back</a></p>' if back else ""
    return f"<!doctype html><meta charset=utf-8><title>Exchange mail connector</title><style>{_STYLE}</style><h1>Exchange mail connector</h1><p>{html.escape(message)}</p>{extra}"


def _login_form(*, action: str, txn: str | None) -> str:
    hidden = f'<input type=hidden name=txn value="{html.escape(txn)}">' if txn else ""
    return f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Connect your work mailbox</title><style>{_STYLE}</style>
<h1>Connect your work mailbox</h1>
<p>Sign in with your <b>company Exchange</b> login. The password is checked against the mail server, then
stored encrypted on this connector so your AI can read your mailbox. 用公司 Exchange 帳號登入；密碼會先經郵件伺服器驗證，再加密儲存在此連接器。</p>
<form method=post action="{action}" autocomplete=on>{hidden}
<label for=email>Work e-mail 公司電郵</label>
<input id=email name=email type=email required autocomplete=username inputmode=email>
<label for=username>Login name, if different 登入名稱（如與電郵不同）</label>
<input id=username name=username type=text placeholder="DOMAIN\\name or name@company" autocomplete=off>
<label for=password>Password 密碼</label>
<input id=password name=password type=password required autocomplete=current-password>
<button type=submit>Connect 連接</button>
</form>
<div class=note>This connector is <b>read-only</b>: it can list, search and read mail, and nothing else. It cannot
send, delete, move or mark mail. 此連接器只能讀取，不能寄出、刪除、移動或標記郵件。</div>
"""


def _mailboxes_form() -> str:
    return f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Additional mailboxes</title><style>{_STYLE}</style>
<h1>Additional mailboxes 其他信箱</h1>
<p>Connect another <b>company Exchange</b> mailbox that has its own login, such as a department mailbox, so your
AI can read it too. Adding it again with a new password updates it. 連接另一個有獨立密碼的公司信箱（例如部門公用信箱）；
用新密碼再加一次即可更新。</p>
<form method=post action="/mailboxes" autocomplete=off>
<label for=owner_email>Your main work e-mail 你的主信箱</label>
<input id=owner_email name=owner_email type=email required autocomplete=username inputmode=email>
<label for=owner_password>Its password 主信箱密碼</label>
<input id=owner_password name=owner_password type=password required autocomplete=current-password>
<label for=action>Action 動作</label>
<select id=action name=action><option value=add>Add or update 新增／更新</option><option value=remove>Remove 移除</option></select>
<label for=email>Mailbox e-mail 信箱地址</label>
<input id=email name=email type=email required inputmode=email>
<label for=username>Login name, if different 登入名稱（如與電郵不同）</label>
<input id=username name=username type=text placeholder="leave blank 留空">
<label for=password>Mailbox password (not needed to remove) 信箱密碼（移除時不用填）</label>
<input id=password name=password type=password autocomplete=new-password>
<button type=submit>Save 儲存</button>
</form>
<div class=note>Read-only, like your main mailbox. Each password is checked once against the mail server and stored
encrypted. If one stops working, only that mailbox stops; enter it again here. 只能讀取；密碼經伺服器驗證後加密儲存。</div>
"""
