"""Local stand-in for the target form + the 2captcha API, used by the tests.

Mirrors the real page: per-session form_token, hidden per-type fields, required terms checkbox,
reCAPTCHA sitekey, plus a honeypot field that must stay empty.
"""
import itertools
import secrets
import threading

from flask import Flask, request, session
from werkzeug.serving import make_server

SITE_KEY = "6LfiehouAAAAAFr7759Kztp8FRrwjs0BRxuMZP28"
FORM = """<!doctype html><html><head><title>Report suspicious activity</title>
<script src="https://www.google.com/recaptcha/api.js" async defer></script></head><body>
{alert}
<form method="post" action="/submit" enctype="multipart/form-data">
  <input type="hidden" name="form_token" value="{token}">
  <div class="hp" aria-hidden="true"><label>Website</label><input type="text" name="website" tabindex="-1" autocomplete="off"></div>
  <div class="field"><label class="title" for="submission_type">Submission Type</label>
    <select id="submission_type" name="submission_type" class="js-dd">
      <option value="raw">Raw source</option><option value="domain" selected>Domain</option>
      <option value="ip">IP</option><option value="url">URL</option></select></div>
  <div class="field" data-type="raw" hidden><textarea name="raw_source"></textarea></div>
  <div class="field" data-type="domain"><label class="title">Domain</label><input type="text" name="domain" value="">{err_domain}</div>
  <div class="field" data-type="ip" hidden><input type="text" name="ip" value=""></div>
  <div class="field" data-type="url" hidden><input type="text" name="url" value=""></div>
  <div class="field"><select id="threat_type" name="threat_type" required class="js-dd">
      <option value="" disabled selected>Please select a threat type</option>
      <option value="Spam">Spam</option><option value="Phishing">Phishing</option>
      <option value="Malware">Malware</option><option value="Botnet C&amp;C">Botnet C&amp;C</option>
      <option value="Fraud / Scam">Fraud / Scam</option><option value="Other">Other</option></select></div>
  <div class="field"><textarea id="reason" name="reason" required></textarea></div>
  <div class="field"><input type="file" id="attachment" name="attachment" accept=".jpg,.jpeg,.png,.pdf"></div>
  <div class="field"><label class="check"><input type="checkbox" name="accept_terms" value="1" required> I accept</label></div>
  <div class="captcha"><div class="g-recaptcha" data-sitekey="{sitekey}"></div></div>
  <button type="submit">Submit</button>
</form></body></html>"""
SUCCESS = """<!doctype html><html><head><title>Thank you</title></head><body>
<main><h1>Thank you</h1><p>Your report has been received. Confirmation code: <b class="mono">{code}</b></p></main></body></html>"""


class MockSite:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test"
        self.submissions: list[dict] = []
        self.captcha_tasks: dict[int, str] = {}
        self.bad_tokens_left = 0       # how many next captcha solutions should be rejected by the site
        self.throttle_left = 0         # how many next submissions get "429 Too Many Requests"
        self.reported_bad: list[int] = []
        self.balance = 3.5
        self._ids = itertools.count(1000)
        self.lock = threading.Lock()
        self._routes()

    def _page(self, alert="", err_domain=""):
        session["token"] = secrets.token_urlsafe(16)
        return FORM.format(token=session["token"], sitekey=SITE_KEY, err_domain=err_domain,
                           alert=f'<div class="alert">{alert}</div>' if alert else "")

    def _routes(self):
        app = self.app

        @app.get("/")
        def index():
            return self._page()

        @app.post("/submit")
        def submit():
            with self.lock:
                throttle = self.throttle_left > 0
                self.throttle_left -= throttle
            if throttle:
                return '<div class="alert">Too many requests, try again later.</div>', 429
            f = request.form
            if not session.get("token") or f.get("form_token") != session.pop("token"):
                return self._page("Your session has expired. Please try again."), 400
            if f.get("website"):
                return self._page("Submission rejected."), 400
            if f.get("g-recaptcha-response") != "valid-token":
                return self._page("Captcha verification failed. Please try again."), 400
            if f.get("accept_terms") != "1":
                return self._page("You must accept the terms."), 400
            kind = f.get("submission_type")
            target = f.get(kind, "")
            if kind == "domain" and target.endswith(".invalid"):
                return self._page(err_domain='<div class="field-error">This domain cannot be reported.</div>'), 400
            up = request.files.get("attachment")
            with self.lock:
                code = f"CF-{next(self._ids):08X}"
                self.submissions.append({"kind": kind, "target": target, "threat": f.get("threat_type"),
                                         "reason": f.get("reason"), "code": code,
                                         "file": (up.filename, len(up.read())) if up and up.filename else None})
            return SUCCESS.format(code=code)

        # ---- fake 2captcha ----
        @app.post("/2captcha/createTask")
        def create_task():
            body = request.get_json()
            if body["clientKey"] != "good-key":
                return {"errorId": 1, "errorCode": "ERROR_KEY_DOES_NOT_EXIST"}
            assert body["task"]["websiteKey"] == SITE_KEY
            with self.lock:
                tid = next(self._ids)
                bad = self.bad_tokens_left > 0
                self.bad_tokens_left -= bad
                self.captcha_tasks[tid] = "wrong-token" if bad else "valid-token"
            return {"errorId": 0, "taskId": tid}

        @app.post("/2captcha/getTaskResult")
        def get_result():
            tid = request.get_json()["taskId"]
            return {"errorId": 0, "status": "ready", "solution": {"gRecaptchaResponse": self.captcha_tasks[tid]}}

        @app.post("/2captcha/reportIncorrect")
        def report():
            self.reported_bad.append(request.get_json()["taskId"])
            return {"errorId": 0, "status": "success"}

        @app.post("/2captcha/getBalance")
        def balance():
            if request.get_json()["clientKey"] != "good-key":
                return {"errorId": 1, "errorCode": "ERROR_KEY_DOES_NOT_EXIST"}
            return {"errorId": 0, "balance": self.balance}

    def start(self) -> str:
        self.server = make_server("127.0.0.1", 0, self.app, threaded=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.server.server_port}"

    def stop(self):
        self.server.shutdown()
