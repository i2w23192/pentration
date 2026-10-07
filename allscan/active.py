"""Active probing (detection mode) — confirm weaknesses, never exploit them.

This module is the opt-in "active" profile. It sends requests whose only
purpose is to *detect and report* a weakness using benign marker payloads and
response / error / timing signatures. It never extracts data, alters state,
gains a shell, or follows an exploit through.

HARD SAFETY CONTROLS (all enforced here):

* **Gated** — does nothing unless ``config.active`` is True (the ``--active``
  flag / TUI toggle) *and* the global authorization gate has already passed.
* **Scope-enforced** — every request's host is checked against a
  :class:`~allscan.scope.ScopeGuard`; out-of-scope hosts are blocked and logged.
* **Rate-limited & concurrency-capped** — reuses the global rate limiter and a
  conservative active-only worker cap.
* **Kill switch & cancel** — honours the shared cancel token (TUI Stop / Ctrl+C).
* **Automatic stop condition** — halts active probing after a configurable run
  of consecutive request errors.
* **Non-destructive** — markers are inert (alphanumeric reflect tokens, a single
  quote for error-based signatures, a ``.invalid`` redirect target that can
  never resolve). No payload changes server state.

Each finding carries: ``{type, location, severity, evidence, confidence,
note="manual validation required"}``.
"""

from __future__ import annotations

import concurrent.futures
import re
import secrets
import threading
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity
from allscan.scope import ScopeGuard

try:
    import requests  # type: ignore
    from requests.exceptions import RequestException  # type: ignore
except Exception:  # pragma: no cover
    requests = None
    RequestException = Exception


REDIRECT_PARAMS = {"next", "url", "redirect", "redirect_uri", "return", "returnurl",
                   "return_to", "dest", "destination", "continue", "r", "u", "goto",
                   "to", "out", "view", "target"}

# SQL error signatures (error-based detection only — a single quote triggers a
# parser error; no UNION/stacked queries, no data extraction).
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"ora-0\d{4}",
    r"postgresql.*error",
    r"pg_query\(\)",
    r"sqlite(3)?::|sqlite3\.operationalerror|sqlite error",
    r"microsoft (odbc|ole db|sql server)",
    r"odbc sql server driver",
    r"syntax error at or near",
    r"sqlstate\[",
]

# Path-disclosure / file-handling error signatures (traversal influence),
# detected WITHOUT requesting real system files.
PATH_ERROR_SIGNATURES = [
    r"failed to open stream",
    r"no such file or directory",
    r"open_basedir restriction",
    r"java\.io\.filenotfoundexception",
    r"system\.io\.filenotfoundexception",
    r"/var/www/|/usr/share/|/home/\w+/|c:\\\\(inetpub|windows)",
]

MARKER_PREFIX = "allscanprobe"
OOB_REDIR = "https://allscan-oob.invalid/probe"


class ActiveContext:
    """Per-run active-probing state: kill switch, error budget, caps."""

    def __init__(self, ctx: ModuleContext):
        self.cap = max(1, min(ctx.config.threads,
                              int(getattr(ctx.config, "active_max_concurrency", 8))))
        self.max_urls = int(getattr(ctx.config, "active_max_urls", 25))
        self.max_params = int(getattr(ctx.config, "active_max_params", 6))
        self.stop_after_errors = int(getattr(ctx.config, "active_stop_after_errors", 25))
        self._errors = 0
        self._lock = threading.Lock()
        self._stopped = threading.Event()

    def record_error(self) -> None:
        with self._lock:
            self._errors += 1
            if self._errors >= self.stop_after_errors:
                self._stopped.set()

    def record_ok(self) -> None:
        with self._lock:
            self._errors = 0  # consecutive-error budget

    def stopped(self) -> bool:
        return self._stopped.is_set()


class ActiveModule(Module):
    name = "active"
    label = "Active Probing (detection)"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        # --- gate 1: must be explicitly enabled -------------------------
        if not getattr(ctx.config, "active", False):
            ctx.log("Active probing disabled (enable with --active). Skipping.")
            return [
                ctx.emit(
                    Finding(
                        category=Category.ACTIVE,
                        title="Active probing disabled",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="Active checks are opt-in. Re-run with --active "
                                    "(and authorization) to enable detection-mode probing.",
                        module=self.name,
                    )
                )
            ]
        if requests is None:
            ctx.log("requests not installed; active probing unavailable.")
            return []

        guard = ScopeGuard(
            target=ctx.target,
            allow=list(getattr(ctx.config, "scope_allow", []) or []),
            deny=list(getattr(ctx.config, "scope_deny", []) or []),
        )
        # --- gate 2: production warning ---------------------------------
        if guard.looks_production() and not getattr(ctx.config, "allow_production", False):
            ctx.log("WARNING: target looks like PRODUCTION. Active probing proceeds "
                    "non-destructively; pass allow_production to silence this warning.")

        actx = ActiveContext(ctx)
        ctx.log(f"Active probing ENABLED — detection-only, scope={ctx.target} "
                f"(+{len(guard.allow)} allow / {len(guard.deny)} deny), "
                f"cap={actx.cap}, stop-after-errors={actx.stop_after_errors}.")

        urls = self._candidate_urls(ctx, guard, actx)
        if not urls:
            ctx.log("No in-scope URLs to actively probe.")
            return []

        findings: list[Finding] = []
        lock = threading.Lock()

        def work(url: str) -> list[Finding]:
            if ctx.cancel.cancelled() or actx.stopped():
                return []
            local: list[Finding] = []
            local += self._check_reflection(ctx, guard, actx, url)
            local += self._check_open_redirect(ctx, guard, actx, url)
            local += self._check_sqli_error(ctx, guard, actx, url)
            local += self._check_dir_listing(ctx, guard, actx, url)
            local += self._check_cors(ctx, guard, actx, url)
            local += self._check_host_header(ctx, guard, actx, url)
            return local

        with concurrent.futures.ThreadPoolExecutor(max_workers=actx.cap) as ex:
            futures = [ex.submit(work, u) for u in urls]
            for fut in concurrent.futures.as_completed(futures):
                if ctx.cancel.cancelled():
                    break
                for f in fut.result():
                    with lock:
                        findings.append(ctx.emit(f))

        # token analysis over observed cookies/headers/bodies (no requests)
        for f in self._check_jwt(ctx):
            findings.append(f)

        if actx.stopped():
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.ACTIVE,
                        title="Active probing stopped early (error threshold reached)",
                        severity=Severity.INFO,
                        target=ctx.target,
                        description="The automatic stop condition halted active probing "
                                    f"after {actx.stop_after_errors} consecutive request errors.",
                        module=self.name,
                    )
                )
            )
        ctx.log(f"Active probing complete — {len(findings)} finding(s).")
        return findings

    # ------------------------------------------------------------------ #
    # request helper with scope enforcement
    # ------------------------------------------------------------------ #
    def _request(self, ctx, guard, actx, url, *, allow_redirects=False):
        host = urlparse(url).hostname or ""
        decision = guard.decide(host)
        if not decision.allowed:
            ctx.audit.record("scope_blocked", url, reason=decision.reason)
            return None
        if ctx.cancel.cancelled() or actx.stopped():
            return None
        ctx.rate()
        ctx.audit.record("active_request", url)
        try:
            resp = requests.get(
                url, timeout=ctx.config.timeout,
                headers={"User-Agent": ctx.config.user_agent},
                allow_redirects=allow_redirects, verify=ctx.config.verify_tls,
            )
            actx.record_ok()
            return resp
        except RequestException:
            actx.record_error()
            return None

    # ------------------------------------------------------------------ #
    def _candidate_urls(self, ctx, guard, actx) -> list[str]:
        """Collect in-scope URLs to probe: live web bases + any param-bearing
        URLs seen in captured page bodies."""
        urls: list[str] = []
        seen: set[str] = set()

        def add(u: str):
            if u not in seen and guard.check(urlparse(u).hostname or ""):
                seen.add(u)
                urls.append(u)

        for base in (ctx.state.get("web_hosts") or []):
            add(base)
        for base, page in (ctx.state.get("pages") or {}).items():
            add(base)
            body = page.get("body") or ""
            for m in re.findall(r"""https?://[^\s"'<>()]+\?[^\s"'<>()]+""", body):
                add(m)
        if not urls:
            add(f"https://{ctx.target}")
            add(f"http://{ctx.target}")
        return urls[: actx.max_urls]

    def _params(self, url: str) -> list[tuple[str, str]]:
        return parse_qsl(urlparse(url).query, keep_blank_values=True)

    def _with_param(self, url: str, key: str, value: str) -> str:
        parts = urlparse(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[key] = value
        return urlunparse(parts._replace(query=urlencode(q)))

    # ------------------------------------------------------------------ #
    # detection checks (all benign, non-destructive)
    # ------------------------------------------------------------------ #
    def _check_reflection(self, ctx, guard, actx, url) -> list[Finding]:
        params = self._params(url)[: actx.max_params]
        # if no params, test a single synthetic one to see if arbitrary input reflects
        if not params:
            params = [("allscanq", "")]
        out: list[Finding] = []
        for key, _ in params:
            if ctx.cancel.cancelled() or actx.stopped():
                break
            marker = MARKER_PREFIX + secrets.token_hex(4)
            test = self._with_param(url, key, marker)
            resp = self._request(ctx, guard, actx, test)
            if resp is None or not resp.text:
                continue
            if marker in resp.text:
                in_script = bool(re.search(r"<script[^>]*>[^<]*" + re.escape(marker),
                                           resp.text, re.IGNORECASE))
                confidence = "high" if in_script else "medium"
                out.append(self._finding(
                    "reflected-input", f"{url} [param={key}]",
                    Severity.MEDIUM if in_script else Severity.LOW,
                    evidence={"param": key, "marker": marker,
                              "status": resp.status_code,
                              "reflected_in_script_context": in_script},
                    confidence=confidence,
                    title=f"Reflected input observed (param '{key}')",
                    description="A benign marker sent in this parameter was reflected "
                                "verbatim in the response — potential XSS sink. No script "
                                "payload was injected.",
                ))
        return out

    def _check_open_redirect(self, ctx, guard, actx, url) -> list[Finding]:
        params = {k for k, _ in self._params(url)} & REDIRECT_PARAMS
        if not params:
            return []
        out: list[Finding] = []
        for key in list(params)[: actx.max_params]:
            if ctx.cancel.cancelled() or actx.stopped():
                break
            test = self._with_param(url, key, OOB_REDIR)
            resp = self._request(ctx, guard, actx, test, allow_redirects=False)
            if resp is None:
                continue
            loc = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and "allscan-oob.invalid" in loc:
                out.append(self._finding(
                    "open-redirect", f"{url} [param={key}]",
                    Severity.MEDIUM,
                    evidence={"param": key, "status": resp.status_code,
                              "location": loc[:200], "marker_host": "allscan-oob.invalid"},
                    confidence="high",
                    title=f"Open redirect appears possible (param '{key}')",
                    description="The server issued a redirect to an attacker-controllable "
                                "value. The marker host is a non-resolvable .invalid domain; "
                                "the redirect was not followed.",
                ))
        return out

    def _check_sqli_error(self, ctx, guard, actx, url) -> list[Finding]:
        params = self._params(url)[: actx.max_params]
        if not params:
            return []
        out: list[Finding] = []
        for key, orig in params:
            if ctx.cancel.cancelled() or actx.stopped():
                break
            # baseline (original value) to avoid flagging pre-existing errors
            base = self._request(ctx, guard, actx, self._with_param(url, key, orig or "1"))
            base_text = (base.text.lower() if base is not None and base.text else "")
            probe = self._request(ctx, guard, actx, self._with_param(url, key, (orig or "1") + "'"))
            if probe is None or not probe.text:
                continue
            text = probe.text.lower()
            for sig in SQL_ERROR_SIGNATURES:
                if re.search(sig, text) and not re.search(sig, base_text):
                    out.append(self._finding(
                        "sql-injection", f"{url} [param={key}]",
                        Severity.HIGH,
                        evidence={"param": key, "signature": sig,
                                  "status": probe.status_code,
                                  "technique": "error-based (single quote)"},
                        confidence="medium",
                        title=f"Parameter appears injectable (SQL error, param '{key}')",
                        description="Appending a single quote produced a database error "
                                    "signature absent from the baseline response. Detection "
                                    "only — no data was extracted and no stacked/UNION query "
                                    "was sent.",
                    ))
                    break
        return out

    def _check_dir_listing(self, ctx, guard, actx, url) -> list[Finding]:
        # confirm directory listing on the URL's own path
        resp = self._request(ctx, guard, actx, url)
        if resp is None or resp.status_code != 200 or not resp.text:
            return []
        if any(m in resp.text for m in ("Index of /", "<title>Directory listing for",
                                        "Parent Directory</a>")):
            return [self._finding(
                "directory-listing", url, Severity.MEDIUM,
                evidence={"status": resp.status_code},
                confidence="high",
                title="Directory listing enabled (confirmed)",
                description="The server returned an auto-generated directory index "
                            "(confirmed by active request).",
            )]
        return []

    def _check_cors(self, ctx, guard, actx, url) -> list[Finding]:
        """Reflected-origin CORS misconfig: send an arbitrary Origin and see if
        it is reflected with credentials allowed. Benign header only."""
        host = urlparse(url).hostname or ""
        decision = guard.decide(host)
        if not decision.allowed:
            ctx.audit.record("scope_blocked", url, reason=decision.reason)
            return []
        if ctx.cancel.cancelled() or actx.stopped():
            return []
        evil = "https://allscan-cors.invalid"
        ctx.rate()
        ctx.audit.record("active_request", url, check="cors")
        try:
            resp = requests.get(url, timeout=ctx.config.timeout,
                                headers={"User-Agent": ctx.config.user_agent,
                                         "Origin": evil},
                                allow_redirects=False, verify=ctx.config.verify_tls)
            actx.record_ok()
        except RequestException:
            actx.record_error()
            return []
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == evil or acao == "*":
            reflects = acao == evil
            sev = Severity.HIGH if (reflects and acac == "true") else (
                Severity.MEDIUM if reflects else Severity.LOW)
            return [self._finding(
                "cors-misconfig", url, sev,
                evidence={"acao": acao, "acac": acac, "sent_origin": evil,
                          "reflects_arbitrary_origin": reflects},
                confidence="high" if reflects else "medium",
                title="Permissive CORS policy" + (" with credentials" if acac == "true" else ""),
                description="The server reflected an arbitrary Origin in "
                            "Access-Control-Allow-Origin" +
                            (" and allows credentials — cross-origin data exposure risk."
                             if acac == "true" else " (or uses a wildcard)."),
            )]
        return []

    def _check_host_header(self, ctx, guard, actx, url) -> list[Finding]:
        """Host-header injection: send a marker Host and see if it is reflected
        in the body or a redirect (cache-poisoning / routing indicator)."""
        host = urlparse(url).hostname or ""
        decision = guard.decide(host)
        if not decision.allowed:
            ctx.audit.record("scope_blocked", url, reason=decision.reason)
            return []
        if ctx.cancel.cancelled() or actx.stopped():
            return []
        marker = "allscan-hh.invalid"
        ctx.rate()
        ctx.audit.record("active_request", url, check="host-header")
        try:
            resp = requests.get(url, timeout=ctx.config.timeout,
                                headers={"User-Agent": ctx.config.user_agent,
                                         "Host": marker},
                                allow_redirects=False, verify=ctx.config.verify_tls)
            actx.record_ok()
        except RequestException:
            actx.record_error()
            return []
        loc = resp.headers.get("Location", "")
        body_head = (resp.text or "")[:4000]
        if marker in loc or marker in body_head:
            where = "redirect Location" if marker in loc else "response body"
            return [self._finding(
                "host-header-injection", url, Severity.MEDIUM,
                evidence={"marker": marker, "status": resp.status_code,
                          "reflected_in": where, "location": loc[:200]},
                confidence="medium",
                title="Host header reflected (possible host-header injection)",
                description=f"A spoofed Host header was reflected in the {where} — "
                            "can enable cache poisoning or password-reset poisoning.",
            )]
        return []

    def _check_jwt(self, ctx) -> list[Finding]:
        """Analyse any JWTs observed in captured cookies/headers/bodies. Decodes
        (does NOT verify) header/payload and flags weak settings. No requests."""
        import base64
        import json as _json

        out: list[Finding] = []
        seen: set[str] = set()
        blobs: list[str] = []
        for base, page in (ctx.state.get("pages") or {}).items():
            blobs.append(page.get("body") or "")
            for k, v in (page.get("headers") or {}).items():
                blobs.append(f"{k}: {v}")
            for c in page.get("cookies") or []:
                blobs.append(str(c))
        jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")
        for blob in blobs:
            for m in jwt_re.findall(blob):
                if m in seen:
                    continue
                seen.add(m)
                try:
                    h_b64 = m.split(".")[0]
                    header = _json.loads(base64.urlsafe_b64decode(h_b64 + "==="))
                except Exception:
                    continue
                alg = str(header.get("alg", "")).lower()
                issues = []
                if alg == "none":
                    issues.append("alg=none (signature not verified)")
                if alg in ("hs256", "hs384", "hs512"):
                    issues.append(f"symmetric alg {alg} (key-confusion risk if RS expected)")
                sev = Severity.HIGH if alg == "none" else (
                    Severity.LOW if issues else Severity.INFO)
                out.append(self._finding(
                    "jwt-analysis", "(observed token)", sev,
                    evidence={"alg": header.get("alg"), "header": header,
                              "issues": issues, "token_prefix": m[:12] + "…"},
                    confidence="medium" if issues else "low",
                    title=f"JWT observed (alg={header.get('alg')})"
                          + (" — weak settings" if issues else ""),
                    description="A JSON Web Token was observed and its header decoded "
                                "(not verified). " + ("; ".join(issues) if issues else
                                "No obvious header weaknesses."),
                ))
        return out

    # ------------------------------------------------------------------ #
    def _finding(self, ftype, location, severity, *, evidence, confidence,
                 title, description) -> Finding:
        ev = dict(evidence)
        ev["type"] = ftype
        return Finding(
            category=Category.ACTIVE,
            title=title,
            severity=severity,
            target=location.split(" ")[0],
            description=description,
            evidence=ev,
            location=location,
            confidence=confidence,
            note="manual validation required",
            module=self.name,
        )
