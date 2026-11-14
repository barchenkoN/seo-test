"""Web UI + JSON API. Start with `python app.py` and open http://localhost:8000"""
import csv
import io
import json
import logging
import threading
import time
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request

from bot import config
from bot.captcha import CaptchaError, TwoCaptcha
from bot.jobs import JobManager
from bot.submitter import Attachment, FormSubmitter, SubmitError
from bot.validation import SUBMISSION_TYPES, parse_targets, validate_attachment, validate_target

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

DEFAULT_THREATS = ["Spam", "Phishing", "Malware", "Botnet C&C", "Fraud / Scam", "Other"]
MAX_TARGETS = 500


def create_app(manager: JobManager | None = None, solver: TwoCaptcha | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_FILE_SIZE + 2 * 1024 * 1024
    solver = solver or TwoCaptcha(config.TWOCAPTCHA_API_KEY)
    manager = manager or JobManager(FormSubmitter(solver))
    settings_path = manager.data_dir / "settings.json"
    if not solver.api_key and settings_path.is_file():  # key saved from the UI earlier
        try:
            solver.api_key = json.loads(settings_path.read_text(encoding="utf-8")).get("twocaptcha_key", "")
        except (OSError, ValueError):
            pass
    meta_cache: dict = {"at": 0.0, "threats": DEFAULT_THREATS, "live": False}
    meta_lock = threading.Lock()

    def threat_types() -> tuple[list[str], bool]:
        """Threat types are read from the live form so the UI follows the site; cached for 10 min."""
        with meta_lock:
            if time.time() - meta_cache["at"] > 600:
                try:
                    form = manager.submitter.fetch_form()
                    if form.threat_options:
                        meta_cache.update(threats=list(form.threat_options.values()), live=True)
                except SubmitError:
                    meta_cache["live"] = False
                meta_cache["at"] = time.time()
            return meta_cache["threats"], meta_cache["live"]

    @app.get("/")
    def index():
        return render_template("index.html", target_url=manager.submitter.page_url)

    @app.get("/api/meta")
    def meta():
        threats, live = threat_types()
        return jsonify(types=SUBMISSION_TYPES, threats=threats, threats_from_site=live,
                       captcha_key_set=bool(solver.api_key), target_url=manager.submitter.page_url,
                       concurrency=manager.pool._max_workers, max_attempts=manager.max_attempts)

    @app.get("/api/balance")
    def balance():
        try:
            return jsonify(balance=solver.balance())
        except CaptchaError as exc:
            return jsonify(error=str(exc)), 502

    @app.post("/api/settings")
    def save_settings():
        key = ((request.get_json(silent=True) or {}).get("twocaptcha_key") or "").strip()
        if not key:
            return jsonify(error="пустой ключ"), 400
        old, solver.api_key = solver.api_key, key
        try:
            bal = solver.balance()
        except CaptchaError as exc:
            solver.api_key = old
            return jsonify(error=str(exc)), 400
        settings_path.write_text(json.dumps({"twocaptcha_key": key}), encoding="utf-8")
        return jsonify(balance=bal)

    @app.post("/api/jobs")
    def create_job():
        f = request.form
        kind = (f.get("submission_type") or "").lower()
        threat = (f.get("threat_type") or "").strip()
        reason = (f.get("reason") or "").strip()
        targets = parse_targets(f.get("targets", ""))
        errors = {}
        if kind not in SUBMISSION_TYPES:
            errors["submission_type"] = "выберите Domain, IP или URL"
        if not targets:
            errors["targets"] = "введите хотя бы одну цель"
        elif len(targets) > MAX_TARGETS:
            errors["targets"] = f"не больше {MAX_TARGETS} строк за раз"
        if not threat:
            errors["threat_type"] = "выберите Threat Type"
        if not reason:
            errors["reason"] = "укажите причину"
        elif len(reason) > 2000:
            errors["reason"] = "не больше 2000 символов"

        attachment = None
        upload = request.files.get("attachment")
        if upload and upload.filename:
            data = upload.read()
            err, mime = validate_attachment(upload.filename, data)
            if err:
                errors["attachment"] = err
            else:
                attachment = Attachment(upload.filename, data, mime)
        if errors:
            return jsonify(errors=errors), 400

        job = manager.create(kind, targets, threat, reason, attachment)
        return jsonify(manager.snapshot(job.id)), 201

    @app.get("/api/jobs")
    def list_jobs():
        return jsonify(manager.list())

    @app.get("/api/jobs/<job_id>")
    def get_job(job_id):
        try:
            return jsonify(manager.snapshot(job_id))
        except KeyError:
            return jsonify(error="not found"), 404

    @app.post("/api/jobs/<job_id>/retry")
    def retry(job_id):
        body = request.get_json(silent=True) or {}
        idxs = body.get("idxs")
        edits = {int(k): v for k, v in (body.get("edits") or {}).items()}
        try:
            manager.retry(job_id, idxs=[int(i) for i in idxs] if idxs is not None else None, edits=edits)
            return jsonify(manager.snapshot(job_id))
        except KeyError:
            return jsonify(error="not found"), 404

    @app.post("/api/validate")
    def validate():
        body = request.get_json(silent=True) or {}
        kind = body.get("submission_type", "")
        return jsonify([{"target": t, "error": validate_target(kind, t)}
                        for t in parse_targets(body.get("targets", ""))])

    @app.get("/api/jobs/<job_id>.csv")
    def export_csv(job_id):
        try:
            job = manager.snapshot(job_id)
        except KeyError:
            return "not found", 404
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["#", "target", "status", "confirmation", "error", "attempts", "updated"])
        for r in job["rows"]:
            w.writerow([r["idx"] + 1, r["target"], r["status"], r["confirmation"] or "", r["error"] or "",
                        r["attempts"], datetime.fromtimestamp(r["updated_at"]).isoformat(timespec="seconds")])
        return Response("﻿" + buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=job-{job_id}.csv"})

    return app


if __name__ == "__main__":
    from waitress import serve

    logging.info("Файл настроек: %s", config.ENV_FILE or f"не найден ({config.ROOT / '.env'})")
    if config.TWOCAPTCHA_API_KEY:
        logging.info("Ключ 2captcha: %s…%s", config.TWOCAPTCHA_API_KEY[:4], config.TWOCAPTCHA_API_KEY[-4:])
    else:
        logging.warning("TWOCAPTCHA_API_KEY не задан — капча решаться не будет. См. README.")
    logging.info("Открыть: http://localhost:%s  (форма: %s)", config.PORT, config.TARGET_URL)
    serve(create_app(), host=config.HOST, port=config.PORT, threads=8)
