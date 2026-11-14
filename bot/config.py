import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> Path | None:
    """Minimal .env loader so `python app.py` works without extra dependencies.

    Tolerates what Windows Notepad does: a UTF-8 BOM / UTF-16, and a hidden ".txt" extension.
    """
    for candidate in (path, path.with_name(path.name + ".txt")):
        if candidate.is_file():
            break
    else:
        return None
    raw = candidate.read_bytes()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig")
    for line in text.splitlines():
        line = line.strip().lstrip("\ufeff").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        if key.strip().startswith("export "):
            key = key.strip()[7:]
        if value and not os.environ.get(key.strip()):
            os.environ[key.strip()] = value
    return candidate


ENV_FILE = _load_dotenv(ROOT / ".env")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


TARGET_URL = os.environ.get("TARGET_URL", "https://linkreclamatiogrwc.uk/")
TWOCAPTCHA_API_KEY = os.environ.get("TWOCAPTCHA_API_KEY", "").strip()
TWOCAPTCHA_API_URL = os.environ.get("TWOCAPTCHA_API_URL", "https://api.2captcha.com").rstrip("/")
CONCURRENCY = max(1, _int("CONCURRENCY", 5))
MAX_ATTEMPTS = max(1, _int("MAX_ATTEMPTS", 3))
CAPTCHA_TIMEOUT = _int("CAPTCHA_TIMEOUT", 180)
CAPTCHA_POLL_INTERVAL = float(os.environ.get("CAPTCHA_POLL_INTERVAL", "5"))
HTTP_TIMEOUT = _int("HTTP_TIMEOUT", 30)
MAX_TARGETS = max(1, _int("MAX_TARGETS", 1000))
RETRY_BACKOFF = float(os.environ.get("RETRY_BACKOFF", "5"))     # seconds × attempt number between retries
THROTTLE_PAUSE = float(os.environ.get("THROTTLE_PAUSE", "30"))  # global pause when the site rate-limits
CAPTCHA_PRICE = float(os.environ.get("CAPTCHA_PRICE", "0.003"))  # USD per reCAPTCHA, for the estimate only
AVG_SUBMIT_SECONDS = 35                                          # typical time for one row, for the estimate
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = _int("PORT", 8000)
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))

MAX_FILE_SIZE = 2 * 1024 * 1024
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
