"""Fills in and submits the target form over plain HTTP (no browser needed).

Flow for one target:
  1. GET the form page in a fresh session (gives a session cookie + a per-session form_token).
  2. Read the form from the HTML: action, hidden fields, honeypots, field names, reCAPTCHA sitekey.
  3. Solve reCAPTCHA v2 through 2captcha.
  4. POST multipart/form-data exactly like a browser would.
  5. Read the result page: CF-XXXXXXXX confirmation code, or the error text shown to the user.
"""
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Tag

from . import config
from .captcha import CaptchaError, TwoCaptcha

log = logging.getLogger(__name__)

CONFIRMATION_RE = re.compile(r"\bCF-[A-Z0-9]{4,}\b")
HONEYPOT_CLASSES = {"hp", "honeypot", "hpot", "hidden-field"}
HIDDEN_STYLE_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}px", re.I)


class SubmitError(Exception):
    def __init__(self, message: str, retryable: bool = False, bad_captcha: bool = False,
                 throttled: bool = False, response_html: str | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.bad_captcha = bad_captcha
        self.throttled = throttled          # the site is pushing back (429 / Cloudflare): slow everyone down
        self.response_html = response_html


@dataclass
class Attachment:
    filename: str
    data: bytes
    mime: str


@dataclass
class ParsedForm:
    action: str
    hidden: dict[str, str] = field(default_factory=dict)
    honeypots: dict[str, str] = field(default_factory=dict)
    type_field: str = "submission_type"
    type_options: dict[str, str] = field(default_factory=dict)     # value -> label
    target_fields: dict[str, str] = field(default_factory=dict)    # submission type -> input name
    threat_field: str = "threat_type"
    threat_options: dict[str, str] = field(default_factory=dict)   # value -> label
    reason_field: str = "reason"
    file_field: str | None = "attachment"
    checkboxes: dict[str, str] = field(default_factory=dict)       # required checkboxes (terms)
    site_key: str | None = None


def _is_honeypot(el: Tag) -> bool:
    for node in [el, *el.parents]:
        if not isinstance(node, Tag) or node.name == "form":
            break
        classes = {c.lower() for c in node.get("class", [])}
        if classes & HONEYPOT_CLASSES:
            return True
        if HIDDEN_STYLE_RE.search(node.get("style", "")):
            return True
    return False


def _options(select: Tag) -> dict[str, str]:
    return {o.get("value", o.get_text(strip=True)): o.get_text(strip=True)
            for o in select.find_all("option") if not o.has_attr("disabled") and o.get("value", "") != ""}


def parse_form(html: str, page_url: str) -> ParsedForm:
    soup = BeautifulSoup(html, "html.parser")
    form = None
    for f in soup.find_all("form"):
        if (f.get("method") or "").lower() == "post" and f.find(attrs={"name": "reason"}):
            form = f
            break
    form = form or soup.find("form")
    if form is None:
        raise SubmitError("на странице не найдена форма (возможно, сайт изменился или отдаёт заглушку)",
                          retryable=True)

    pf = ParsedForm(action=urljoin(page_url, form.get("action") or page_url))

    for el in form.find_all(["input", "textarea", "select"]):
        name = el.get("name")
        if not name:
            continue
        kind = (el.get("type") or el.name).lower()
        if _is_honeypot(el):
            pf.honeypots[name] = el.get("value", "") if el.name == "input" else ""
        elif kind == "hidden":
            pf.hidden[name] = el.get("value", "")
        elif kind == "checkbox" and el.has_attr("required"):
            pf.checkboxes[name] = el.get("value", "on")
        elif kind == "file":
            pf.file_field = name

    type_select = form.find("select", attrs={"name": "submission_type"})
    if type_select:
        pf.type_options = _options(type_select)
    for block in form.select("[data-type]"):
        inp = block.find(["input", "textarea"])
        if inp and inp.get("name"):
            pf.target_fields[block["data-type"]] = inp["name"]

    threat_select = form.find("select", attrs={"name": "threat_type"})
    if threat_select:
        pf.threat_options = _options(threat_select)

    captcha = soup.find(attrs={"data-sitekey": True})
    if captcha:
        pf.site_key = captcha["data-sitekey"]
    else:
        m = re.search(r"""sitekey['"]?\s*[:=]\s*['"]([\w-]{20,})""", html)
        pf.site_key = m.group(1) if m else None
    return pf


def _visible_text(el: Tag) -> str:
    return " ".join(el.get_text(" ", strip=True).split())


def parse_result(html: str, status: int) -> tuple[str | None, str | None]:
    """Returns (confirmation code, error message)."""
    soup = BeautifulSoup(html, "html.parser")
    for junk in soup(["script", "style", "noscript"]):
        junk.decompose()
    text = _visible_text(soup)

    m = CONFIRMATION_RE.search(text)
    if m:
        return m.group(0), None

    if "Just a moment" in text or "cf-challenge" in html or "Attention Required" in text:
        return None, "Cloudflare показал проверку браузера / заблокировал запрос"

    errors = []
    for alert in soup.select(".alert, .error, .errors, [role=alert]"):
        t = _visible_text(alert)
        if t and t not in errors:
            errors.append(t)
    for fe in soup.select(".field-error, .invalid-feedback, .help-block.error"):
        t = _visible_text(fe)
        container = fe.find_parent(class_="field")
        label = container.find("label") if container else None
        label_text = _visible_text(label) if label else ""
        msg = f"{label_text}: {t}" if label_text and label_text not in t else t
        if msg and msg not in errors:
            errors.append(msg)
    if errors:
        return None, "; ".join(errors)

    if status >= 400:
        return None, f"сервер ответил HTTP {status}: {text[:200]}"
    title = soup.title.get_text(strip=True) if soup.title else ""
    if soup.find("form") and soup.find(attrs={"data-sitekey": True}):
        return None, "сервер вернул форму без кода подтверждения и без текста ошибки"
    return None, f"не найден код подтверждения в ответе ({title or text[:200]})"


def _match_option(options: dict[str, str], wanted: str, what: str) -> str:
    if not options:
        return wanted
    if wanted in options:
        return wanted
    for value, label in options.items():
        if wanted.strip().lower() in (value.lower(), label.lower()):
            return value
    raise SubmitError(f"на сайте нет варианта {what} «{wanted}» (есть: {', '.join(options.values())})")


class FormSubmitter:
    def __init__(self, solver: TwoCaptcha, page_url: str = config.TARGET_URL):
        self.solver = solver
        self.page_url = page_url
        self._cooldown_until = 0.0
        self._cooldown_lock = threading.Lock()

    def cool_down(self, seconds: float) -> None:
        """Pause every worker (not just the one that got the 429), so the site sees the load actually drop."""
        with self._cooldown_lock:
            self._cooldown_until = max(self._cooldown_until, time.monotonic() + seconds)
        log.warning("site is throttling, pausing all submissions for %.0f s", seconds)

    def wait_cooldown(self, on_step=lambda msg: None) -> None:
        delay = self._cooldown_until - time.monotonic()
        if delay > 0:
            on_step(f"пауза {delay:.0f} с: сайт ограничивает запросы")
            time.sleep(delay)

    def _new_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": config.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        return s

    def fetch_form(self, session: requests.Session | None = None) -> ParsedForm:
        session = session or self._new_session()
        try:
            resp = session.get(self.page_url, timeout=config.HTTP_TIMEOUT)
        except requests.RequestException as exc:
            raise SubmitError(f"сайт недоступен: {exc}", retryable=True) from exc
        if resp.status_code != 200:
            throttled = resp.status_code in (403, 429, 503)
            raise SubmitError(f"страница формы вернула HTTP {resp.status_code}", retryable=resp.status_code >= 429
                              or throttled, throttled=throttled, response_html=resp.text)
        return parse_form(resp.text, resp.url)

    def submit(self, submission_type: str, target: str, threat_type: str, reason: str,
               attachment: Attachment | None, on_step=lambda msg: None) -> str:
        """Submits one target. Returns the confirmation code or raises SubmitError/CaptchaError."""
        self.wait_cooldown(on_step)
        session = self._new_session()
        on_step("загрузка формы")
        form = self.fetch_form(session)

        type_value = _match_option(form.type_options, submission_type, "Submission Type")
        threat_value = _match_option(form.threat_options, threat_type, "Threat Type")
        target_field = form.target_fields.get(type_value, type_value)

        data: dict[str, str] = {}
        data.update(form.hidden)
        data.update(form.honeypots)          # honeypots go back untouched (empty)
        data["submission_type"] = type_value
        for other in form.target_fields.values():
            data.setdefault(other, "")       # browser sends the hidden inputs empty
        data[target_field] = target
        data["threat_type"] = threat_value
        data["reason"] = reason
        data.update(form.checkboxes)         # accept_terms=1

        task_id = None
        if form.site_key:
            on_step("решение капчи")
            token, task_id = self.solver.solve_recaptcha_v2(form.site_key, self.page_url, config.USER_AGENT)
            data["g-recaptcha-response"] = token

        if attachment:
            files = {form.file_field or "attachment": (attachment.filename, attachment.data, attachment.mime)}
        else:  # browsers send an empty file part when nothing is selected
            files = {form.file_field or "attachment": ("", b"", "application/octet-stream")}

        on_step("отправка")
        origin = re.match(r"^https?://[^/]+", self.page_url).group(0)
        try:
            resp = session.post(form.action, data=data, files=files, timeout=config.HTTP_TIMEOUT,
                                headers={"Referer": self.page_url, "Origin": origin})
        except requests.ConnectionError as exc:
            raise SubmitError(f"не удалось соединиться с сайтом при отправке: {exc}", retryable=True) from exc
        except requests.Timeout as exc:
            # The request may have gone through: don't resend automatically to avoid a duplicate report.
            raise SubmitError("сайт не ответил на отправку вовремя — неизвестно, принята ли заявка; "
                              "проверьте и при необходимости отправьте повторно") from exc
        except requests.RequestException as exc:
            raise SubmitError(f"ошибка отправки: {exc}", retryable=True) from exc

        code, error = parse_result(resp.text, resp.status_code)
        if code:
            return code

        low = error.lower()
        html = resp.text
        if "captcha" in low or "капч" in low or "robot" in low:
            if task_id:
                self.solver.report_bad(task_id)
            raise SubmitError(f"сайт не принял капчу: {error}", retryable=True, bad_captcha=True, response_html=html)
        if any(w in low for w in ("token", "expired", "session", "csrf")):
            raise SubmitError(f"истёк токен формы: {error}", retryable=True, response_html=html)
        throttled = resp.status_code == 429 or "cloudflare" in low or any(
            w in low for w in ("too many", "rate limit", "slow down", "try again later"))
        if throttled or resp.status_code >= 500:
            raise SubmitError(error, retryable=True, throttled=throttled, response_html=html)
        raise SubmitError(error, response_html=html)


def submit_with_retries(submitter: FormSubmitter, max_attempts: int, on_attempt=lambda n: None,
                        on_step=lambda msg: None, **kwargs) -> str:
    last: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        on_attempt(attempt)
        try:
            return submitter.submit(on_step=on_step, **kwargs)
        except CaptchaError as exc:
            last = exc
            if exc.fatal:
                raise
        except SubmitError as exc:
            last = exc
            if not exc.retryable:
                raise
            if exc.throttled:
                submitter.cool_down(config.THROTTLE_PAUSE * attempt)
        log.warning("attempt %s/%s failed: %s", attempt, max_attempts, last)
        if attempt < max_attempts and not getattr(last, "bad_captcha", False):
            time.sleep(config.RETRY_BACKOFF * attempt)  # 5 s, 10 s, ... before trying the site again
    raise last  # type: ignore[misc]
