"""Batch jobs: one job = one operator submission with N target lines; each line is sent separately."""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import config
from .captcha import CaptchaError
from .submitter import Attachment, FormSubmitter, SubmitError, submit_with_retries
from .validation import validate_target

log = logging.getLogger(__name__)

QUEUED, RUNNING, SUCCESS, FAILED = "queued", "running", "success", "failed"
CANCELLED_MSG = "отменено оператором"


@dataclass
class Row:
    idx: int
    target: str
    status: str = QUEUED
    step: str = ""
    confirmation: str | None = None
    error: str | None = None
    attempts: int = 0
    updated_at: float = field(default_factory=time.time)
    has_response: bool = False   # the site's reply to a failed attempt is saved for inspection
    run: int = 0                 # bumped on every enqueue so a stale queued task never sends twice


@dataclass
class Job:
    id: str
    created_at: float
    submission_type: str
    threat_type: str
    reason: str
    attachment_name: str | None
    attachment_mime: str | None
    rows: list[Row]
    duplicates: int = 0

    def summary(self) -> dict:
        counts = {s: 0 for s in (QUEUED, RUNNING, SUCCESS, FAILED)}
        for r in self.rows:
            counts[r.status] += 1
        return {"id": self.id, "created_at": self.created_at, "submission_type": self.submission_type,
                "threat_type": self.threat_type, "total": len(self.rows), "duplicates": self.duplicates, **counts}


class JobManager:
    def __init__(self, submitter: FormSubmitter, data_dir: Path = config.DATA_DIR,
                 workers: int = config.CONCURRENCY, max_attempts: int = config.MAX_ATTEMPTS):
        self.submitter = submitter
        self.max_attempts = max_attempts
        self.workers = workers
        self.data_dir = data_dir
        self.uploads = data_dir / "uploads"
        self.responses = data_dir / "responses"
        self.uploads.mkdir(parents=True, exist_ok=True)
        self.responses.mkdir(parents=True, exist_ok=True)
        self.db_path = data_dir / "jobs.json"
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="submit")
        self.jobs: dict[str, Job] = {}
        self._dirty = threading.Event()
        self._load()
        threading.Thread(target=self._saver, daemon=True, name="saver").start()

    # ---------- persistence ----------
    def _load(self) -> None:
        if not self.db_path.exists():
            return
        try:
            raw = json.loads(self.db_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            log.exception("cannot read %s, starting empty", self.db_path)
            return
        for j in raw:
            rows = [Row(**r) for r in j.pop("rows")]
            for r in rows:  # rows interrupted by a restart can be resent manually
                if r.status in (QUEUED, RUNNING):
                    r.status, r.step = FAILED, ""
                    r.error = "отправка прервана перезапуском приложения — отправьте повторно"
            self.jobs[j["id"]] = Job(rows=rows, **j)

    def flush(self) -> None:
        with self.lock:
            payload = json.dumps([asdict(j) for j in self.jobs.values()], ensure_ascii=False)
            self._dirty.clear()
        tmp = self.db_path.with_suffix(".tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(self.db_path)

    def _saver(self) -> None:
        """Row updates are written at most once every 2 s, so big batches don't rewrite the file per row."""
        while True:
            self._dirty.wait()
            time.sleep(2)
            try:
                self.flush()
            except OSError:
                log.exception("cannot save jobs")

    # ---------- public API ----------
    def create(self, submission_type: str, targets: list[str], threat_type: str, reason: str,
               attachment: Attachment | None, duplicates: int = 0) -> Job:
        job_id = uuid.uuid4().hex[:12]
        if attachment:
            (self.uploads / job_id).write_bytes(attachment.data)
        job = Job(id=job_id, created_at=time.time(), submission_type=submission_type, threat_type=threat_type,
                  reason=reason, attachment_name=attachment.filename if attachment else None,
                  attachment_mime=attachment.mime if attachment else None,
                  rows=[Row(idx=i, target=t) for i, t in enumerate(targets)], duplicates=duplicates)
        with self.lock:
            self.jobs[job_id] = job
            for row in job.rows:
                self._enqueue(job, row)
        self.flush()
        return job

    def retry(self, job_id: str, idxs: list[int] | None = None, edits: dict[int, str] | None = None) -> Job:
        """Resend failed rows (all failed ones when idxs is None). `edits` lets the operator fix a value first."""
        job = self.get(job_id)
        with self.lock:
            for row in job.rows:
                if row.status != FAILED or (idxs is not None and row.idx not in idxs):
                    continue
                if edits and row.idx in edits and edits[row.idx].strip():
                    row.target = edits[row.idx].strip()
                row.attempts = 0
                self._enqueue(job, row)
        self.flush()
        return job

    def cancel(self, job_id: str) -> int:
        """Stops rows that have not started yet. Rows already being sent finish normally."""
        job = self.get(job_id)
        n = 0
        with self.lock:
            for row in job.rows:
                if row.status == QUEUED:
                    self._set(row, status=FAILED, error=CANCELLED_MSG, step="")
                    n += 1
        self.flush()
        return n

    def get(self, job_id: str) -> Job:
        with self.lock:
            if job_id not in self.jobs:
                raise KeyError(job_id)
            return self.jobs[job_id]

    def list(self) -> list[dict]:
        with self.lock:
            return [j.summary() for j in sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)]

    def snapshot(self, job_id: str) -> dict:
        with self.lock:
            job = self.get(job_id)
            data = asdict(job)
            data["summary"] = job.summary()
            return data

    def all_snapshots(self) -> list[dict]:
        with self.lock:
            return [self.snapshot(j["id"]) for j in self.list()]

    def response_path(self, job_id: str, idx: int) -> Path:
        return self.responses / f"{job_id}_{idx}.html"

    # ---------- worker ----------
    def _set(self, row: Row, **changes) -> None:
        with self.lock:
            for k, v in changes.items():
                setattr(row, k, v)
            row.updated_at = time.time()
        self._dirty.set()

    def _enqueue(self, job: Job, row: Row) -> None:
        error = validate_target(job.submission_type, row.target)
        if error:  # never spend a captcha on a line that is obviously wrong
            self._set(row, status=FAILED, error=f"неверный формат: {error}", confirmation=None, step="")
            return
        row.run += 1
        self._set(row, status=QUEUED, error=None, confirmation=None, step="в очереди", has_response=False)
        self.pool.submit(self._process, job, row, row.run)

    def _process(self, job: Job, row: Row, run: int) -> None:
        with self.lock:
            if row.run != run or row.status != QUEUED:  # cancelled, or superseded by a newer retry
                return
            self._set(row, status=RUNNING, step="старт")
        attachment = None
        if job.attachment_name:
            attachment = Attachment(job.attachment_name, (self.uploads / job.id).read_bytes(), job.attachment_mime)
        try:
            code = submit_with_retries(
                self.submitter, self.max_attempts,
                on_attempt=lambda n: self._set(row, attempts=row.attempts + 1),
                on_step=lambda s: self._set(row, step=s),
                submission_type=job.submission_type, target=row.target, threat_type=job.threat_type,
                reason=job.reason, attachment=attachment)
            self._set(row, status=SUCCESS, confirmation=code, error=None, step="")
            log.info("job %s row %s %s -> %s", job.id, row.idx + 1, row.target, code)
        except (SubmitError, CaptchaError) as exc:
            html = getattr(exc, "response_html", None)
            if html:
                self.response_path(job.id, row.idx).write_text(html, encoding="utf-8")
            self._set(row, status=FAILED, error=str(exc), step="", has_response=bool(html))
            log.warning("job %s row %s %s failed: %s", job.id, row.idx + 1, row.target, exc)
        except Exception as exc:  # noqa: BLE001 - one broken row must not kill the worker
            log.exception("unexpected error")
            self._set(row, status=FAILED, error=f"внутренняя ошибка: {exc}", step="")
