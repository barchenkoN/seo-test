import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so `python app.py` works without extra dependencies."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


_load_dotenv(ROOT / ".env")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


TARGET_URL = os.environ.get("TARGET_URL", "https://linkreclamatiogrwc.uk/")
TWOCAPTCHA_API_KEY = os.environ.get("TWOCAPTCHA_API_KEY", "").strip()
TWOCAPTCHA_API_URL = os.environ.get("TWOCAPTCHA_API_URL", "https://api.2captcha.com").rstrip("/")
CONCURRENCY = max(1, _int("CONCURRENCY", 3))
MAX_ATTEMPTS = max(1, _int("MAX_ATTEMPTS", 3))
CAPTCHA_TIMEOUT = _int("CAPTCHA_TIMEOUT", 180)
CAPTCHA_POLL_INTERVAL = float(os.environ.get("CAPTCHA_POLL_INTERVAL", "5"))
HTTP_TIMEOUT = _int("HTTP_TIMEOUT", 30)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = _int("PORT", 8000)
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))

MAX_FILE_SIZE = 2 * 1024 * 1024
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
