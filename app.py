"""Web UI + JSON API. Start with `python app.py` and open http://localhost:8000"""
import csv
import io
import json
import hmac
import logging
import logging.handlers
import threading
import time
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request

from bot import config
from bot.captcha import CaptchaError, TwoCaptcha
from bot.jobs import JobManager
from bot.submitter import Attachment, FormSubmitter, SubmitError
from bot.validation import SUBMISSION_TYPES, dedupe, parse_targets, validate_attachment, validate_target

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

DEFAULT_THREATS = ["Spam", "Phishing", "Malware", "Botnet C&C", "Fraud / Scam", "Other"]
CSV_HEADER = ["job", "created", "type", "threat", "#", "target", "status", "confirmation", "error", "attempts", "updated"]


def _ts(t: float) -> str:
    return datetime.fromtimestamp(t).isoformat(sep=" ", timespec="seconds")


def _csv_rows(job: dict):
    for r in job["rows"]:
        yield [job["id"], _ts(job["created_at"]), job["submission_type"], job["threat_type"], r["idx"] + 1,
               r["target"], r["status"], r["confirmation"] or "", r["error"] or "", r["attempts"], _ts(r["updated_at"])]


def _csv_response(jobs: list[dict], filename: str) -> Response:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_HEADER)
    for job in jobs:
        w.writerows(_csv_rows(job))
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",  # BOM so Excel reads UTF-8 correctly
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


def create_app(manager: JobManager | None = None, solver: TwoCaptcha | None = None,
               password: str = config.APP_PASSWORD) -> Flask:
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

    @app.before_request
    def require_password():
        """Optional protection (APP_PASSWORD): anyone who can open the page can spend the 2captcha balance."""
        if not password:
            return None
        auth = request.authorization
        if auth and hmac.compare_digest((auth.password or "").encode(), password.encode()):
            return None
        return Response("Нужен пароль", 401, {"WWW-Authenticate": 'Basic realm="reclamation-bot"'})

    @app.get("/")
    def index():
        return render_template("index.html", target_url=manager.submitter.page_url)

    @app.get("/api/meta")
    def meta():
        threats, live = threat_types()
        return jsonify(types=SUBMISSION_TYPES, threats=threats, threats_from_site=live,
                       captcha_key_set=bool(solver.api_key), target_url=manager.submitter.page_url,
                       concurrency=manager.workers, max_attempts=manager.max_attempts,
                       max_targets=config.MAX_TARGETS, captcha_price=config.CAPTCHA_PRICE,
                       avg_seconds=config.AVG_SUBMIT_SECONDS)

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
        targets, duplicates = dedupe(kind, parse_targets(f.get("targets", "")))
        errors = {}
        if kind not in SUBMISSION_TYPES:
            errors["submission_type"] = "выберите Domain, IP или URL"
        if not targets:
            errors["targets"] = "введите хотя бы одну цель"
        elif len(targets) > config.MAX_TARGETS:
            errors["targets"] = f"не больше {config.MAX_TARGETS} строк за раз (MAX_TARGETS в .env)"
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

        # Check the money before starting, not after 50 identical "zero balance" failures.
        if not solver.api_key:
            return jsonify(error="не задан ключ 2captcha"), 400
        to_send = sum(1 for t in targets if validate_target(kind, t) is None)
        try:
            bal = solver.balance()
            need = to_send * config.CAPTCHA_PRICE
            if bal < need:
                return jsonify(error=f"на балансе 2captcha ${bal:.2f}, а нужно примерно ${need:.2f} "
                                     f"на {to_send} отправок"), 400
        except CaptchaError as exc:
            if exc.fatal:
                return jsonify(error=f"2captcha: {exc}"), 400
            logging.warning("balance check skipped: %s", exc)  # 2captcha hiccup: let the rows retry on their own

        job = manager.create(kind, targets, threat, reason, attachment, duplicates=duplicates)
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

    @app.post("/api/jobs/<job_id>/cancel")
    def cancel(job_id):
        try:
            n = manager.cancel(job_id)
            return jsonify(cancelled=n, **manager.snapshot(job_id))
        except KeyError:
            return jsonify(error="not found"), 404

    @app.get("/api/jobs/<job_id>/rows/<int:idx>/response")
    def row_response(job_id, idx):
        """The site's raw reply to the last failed attempt, shown as text (never rendered on our origin)."""
        path = manager.response_path(job_id, idx)
        if not path.is_file():
            return "нет сохранённого ответа", 404
        return Response(path.read_text(encoding="utf-8"), mimetype="text/plain; charset=utf-8")

    @app.post("/api/validate")
    def validate():
        body = request.get_json(silent=True) or {}
        kind = body.get("submission_type", "")
        all_lines = parse_targets(body.get("targets", ""))
        unique, duplicates = dedupe(kind, all_lines)
        rows = [{"target": t, "error": validate_target(kind, t)} for t in unique]
        return jsonify(rows=rows, duplicates=duplicates, valid=sum(1 for r in rows if not r["error"]))

    @app.get("/api/jobs/<job_id>.csv")
    def export_csv(job_id):
        try:
            return _csv_response([manager.snapshot(job_id)], f"job-{job_id}.csv")
        except KeyError:
            return "not found", 404

    @app.get("/api/export.csv")
    def export_all():
        return _csv_response(manager.all_snapshots(), "all-results.csv")

    return app


if __name__ == "__main__":
    from waitress import serve

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    file_log = logging.handlers.RotatingFileHandler(config.DATA_DIR / "app.log", maxBytes=5_000_000,
                                                    backupCount=3, encoding="utf-8")
    file_log.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(file_log)
    logging.info("Файл настроек: %s", config.ENV_FILE or f"не найден ({config.ROOT / '.env'})")
    if config.TWOCAPTCHA_API_KEY:
        logging.info("Ключ 2captcha: %s…%s", config.TWOCAPTCHA_API_KEY[:4], config.TWOCAPTCHA_API_KEY[-4:])
    else:
        logging.warning("TWOCAPTCHA_API_KEY не задан — капча решаться не будет. См. README.")
    logging.info("Одновременных отправок: %s, попыток на строку: %s%s", config.CONCURRENCY, config.MAX_ATTEMPTS,
                 ", вход по паролю" if config.APP_PASSWORD else "")
    logging.info("Открыть: http://localhost:%s  (форма: %s)", config.PORT, config.TARGET_URL)
    serve(create_app(), host=config.HOST, port=config.PORT, threads=8)
