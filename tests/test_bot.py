import time
from pathlib import Path

import pytest

from app import create_app
from bot import config
from bot.captcha import TwoCaptcha
from bot.jobs import JobManager
from bot.submitter import FormSubmitter, parse_form, parse_result
from bot.validation import validate_attachment, validate_target
from tests.mock_site import MockSite

FIXTURES = Path(__file__).parent / "fixtures"
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 100


# ---------- parsing the real page ----------
def test_parse_real_form():
    form = parse_form((FIXTURES / "real_form.html").read_text(), "https://linkreclamatiogrwc.uk/")
    assert form.action == "https://linkreclamatiogrwc.uk/submit"
    assert form.site_key == "6LfiehouAAAAAFr7759Kztp8FRrwjs0BRxuMZP28"
    assert "form_token" in form.hidden
    assert form.checkboxes == {"accept_terms": "1"}
    assert form.target_fields == {"raw": "raw_source", "domain": "domain", "ip": "ip", "url": "url"}
    assert "Botnet C&C" in form.threat_options
    assert form.file_field == "attachment"


def test_parse_result():
    assert parse_result("<p>Your code: <b>CF-1A2B3C4D</b></p>", 200) == ("CF-1A2B3C4D", None)
    code, err = parse_result('<div class="alert">Captcha verification failed.</div><form></form>', 400)
    assert code is None and "Captcha" in err
    code, err = parse_result('<div class="field"><label>Domain</label><div class="field-error">Bad</div></div>', 400)
    assert err == "Domain: Bad"
    # lowercase cloudflare markers must not be taken for a confirmation code
    assert parse_result('<div class="cf-wrapper">Just a moment...</div>', 403)[0] is None


# ---------- validation ----------
@pytest.mark.parametrize("kind,value,ok", [
    ("domain", "example.com", True), ("domain", "пример.рф", True), ("domain", "sub.example.co.uk", True),
    ("domain", "example", False), ("domain", "https://example.com", False), ("domain", "1.2.3.4", False),
    ("domain", "bad_domain!.com", False),
    ("ip", "192.0.2.1", True), ("ip", "2001:db8::1", True), ("ip", "300.1.1.1", False), ("ip", "example.com", False),
    ("url", "https://example.com/page?a=1", True), ("url", "http://192.0.2.1/x", True),
    ("url", "example.com/page", False), ("url", "ftp://example.com", False),
])
def test_validate_target(kind, value, ok):
    assert (validate_target(kind, value) is None) == ok


def test_validate_attachment():
    assert validate_attachment("a.png", PNG) == (None, "image/png")
    assert validate_attachment("a.pdf", b"%PDF-1.4 ...")[1] == "application/pdf"
    assert validate_attachment("a.gif", PNG)[0]
    assert validate_attachment("a.jpg", PNG)[0]                       # wrong content
    assert validate_attachment("a.png", PNG + b"\0" * (2 * 1024 * 1024))[0]  # > 2 MB


# ---------- end-to-end against the mock site ----------
@pytest.fixture
def env(tmp_path, monkeypatch):
    site = MockSite()
    base = site.start()
    monkeypatch.setattr(config, "HTTP_TIMEOUT", 5)
    solver = TwoCaptcha("good-key", api_url=f"{base}/2captcha", poll_interval=0)
    manager = JobManager(FormSubmitter(solver, page_url=f"{base}/"), data_dir=tmp_path, workers=3, max_attempts=3)
    client = create_app(manager, solver).test_client()
    yield site, client, manager, solver
    site.stop()


def wait_done(client, job_id, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get(f"/api/jobs/{job_id}").get_json()
        if job["summary"]["queued"] + job["summary"]["running"] == 0:
            return job
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_batch_submit_one_per_line(env):
    site, client, *_ = env
    from io import BytesIO
    resp = client.post("/api/jobs", data={
        "submission_type": "domain", "targets": "a.example.com\n\nb.example.com\nnot a domain\nc.example.com\n",
        "threat_type": "Phishing", "reason": "phishing kit", "attachment": (BytesIO(PNG), "shot.png")})
    assert resp.status_code == 201
    job = wait_done(client, resp.get_json()["id"])
    rows = {r["target"]: r for r in job["rows"]}
    assert len(rows) == 4
    for t in ("a.example.com", "b.example.com", "c.example.com"):
        assert rows[t]["status"] == "success" and rows[t]["confirmation"].startswith("CF-")
    assert rows["not a domain"]["status"] == "failed" and "неверный формат" in rows["not a domain"]["error"]
    assert sorted(s["target"] for s in site.submissions) == ["a.example.com", "b.example.com", "c.example.com"]
    assert all(s["file"] == ("shot.png", len(PNG)) and s["threat"] == "Phishing" for s in site.submissions)


def test_ip_and_url_types(env):
    site, client, *_ = env
    for kind, target in (("ip", "192.0.2.10"), ("url", "https://example.com/login")):
        job_id = client.post("/api/jobs", data={"submission_type": kind, "targets": target,
                                                "threat_type": "Malware", "reason": "r"}).get_json()["id"]
        assert wait_done(client, job_id)["rows"][0]["status"] == "success"
    assert [(s["kind"], s["target"], s["file"]) for s in site.submissions] == [
        ("ip", "192.0.2.10", None), ("url", "https://example.com/login", None)]


def test_rejected_captcha_is_reported_and_retried(env):
    site, client, *_ = env
    site.bad_tokens_left = 2
    job_id = client.post("/api/jobs", data={"submission_type": "domain", "targets": "x.example.com",
                                            "threat_type": "Spam", "reason": "r"}).get_json()["id"]
    row = wait_done(client, job_id)["rows"][0]
    assert row["status"] == "success" and row["attempts"] == 3
    assert len(site.reported_bad) == 2


def test_site_error_and_manual_retry_with_edit(env):
    site, client, *_ = env
    job_id = client.post("/api/jobs", data={"submission_type": "domain", "targets": "evil.invalid\nok.example.com",
                                            "threat_type": "Spam", "reason": "r"}).get_json()["id"]
    rows = wait_done(client, job_id)["rows"]
    assert rows[0]["status"] == "failed" and rows[0]["error"] == "Domain: This domain cannot be reported."
    assert rows[0]["attempts"] == 1                 # site validation errors are not auto-retried
    assert rows[1]["status"] == "success"

    client.post(f"/api/jobs/{job_id}/retry", json={"idxs": [0], "edits": {"0": "fixed.example.com"}})
    rows = wait_done(client, job_id)["rows"]
    assert rows[0]["status"] == "success" and rows[0]["target"] == "fixed.example.com"
    assert len(site.submissions) == 2               # the successful row was not resent


def test_bad_captcha_key_is_fatal(env):
    site, client, manager, solver = env
    solver.api_key = "bad-key"
    job_id = client.post("/api/jobs", data={"submission_type": "domain", "targets": "x.example.com",
                                            "threat_type": "Spam", "reason": "r"}).get_json()["id"]
    row = wait_done(client, job_id)["rows"][0]
    assert row["status"] == "failed" and "неверный ключ 2captcha" in row["error"] and row["attempts"] == 1


def test_form_validation_errors(env):
    _, client, *_ = env
    resp = client.post("/api/jobs", data={"submission_type": "domain", "targets": "", "threat_type": "", "reason": ""})
    assert resp.status_code == 400
    assert set(resp.get_json()["errors"]) == {"targets", "threat_type", "reason"}


def test_meta_reads_threats_from_site_and_csv(env):
    _, client, *_ = env
    meta = client.get("/api/meta").get_json()
    assert meta["threats_from_site"] and "Fraud / Scam" in meta["threats"]
    assert client.get("/api/balance").get_json() == {"balance": 3.5}
    job_id = client.post("/api/jobs", data={"submission_type": "domain", "targets": "a.example.com",
                                            "threat_type": "Spam", "reason": "r"}).get_json()["id"]
    wait_done(client, job_id)
    csv_text = client.get(f"/api/jobs/{job_id}.csv").get_data(as_text=True)
    assert "a.example.com,success,CF-" in csv_text


def test_restart_marks_interrupted_rows_failed(tmp_path):
    import json
    (tmp_path / "jobs.json").write_text(json.dumps([{
        "id": "j1", "created_at": 0, "submission_type": "domain", "threat_type": "Spam", "reason": "r",
        "attachment_name": None, "attachment_mime": None,
        "rows": [{"idx": 0, "target": "a.com", "status": "running", "step": "", "confirmation": None,
                  "error": None, "attempts": 1, "updated_at": 0}]}]))
    m = JobManager(FormSubmitter(TwoCaptcha("k")), data_dir=tmp_path)
    assert m.get("j1").rows[0].status == "failed"


def test_dotenv_windows_notepad(tmp_path, monkeypatch):
    from bot.config import _load_dotenv
    for i, (name, raw) in enumerate(((".env", "﻿TWOCAPTCHA_API_KEY=k1\r\n".encode("utf-8")),
                      (".env", "TWOCAPTCHA_API_KEY=k2\r\n".encode("utf-16")),
                      (".env.txt", b"TWOCAPTCHA_API_KEY=k3\n"))):
        d = tmp_path / str(i)
        d.mkdir()
        (d / name).write_bytes(raw)
        monkeypatch.delenv("TWOCAPTCHA_API_KEY", raising=False)
        assert _load_dotenv(d / ".env")
        import os
        assert os.environ["TWOCAPTCHA_API_KEY"] == f"k{i + 1}"


def test_key_from_ui(env):
    site, client, manager, solver = env
    solver.api_key = ""
    assert client.post("/api/settings", json={"twocaptcha_key": "bad-key"}).status_code == 400
    assert client.post("/api/settings", json={"twocaptcha_key": "good-key"}).get_json() == {"balance": 3.5}
    assert solver.api_key == "good-key" and (manager.data_dir / "settings.json").is_file()
