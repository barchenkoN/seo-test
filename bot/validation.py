"""Local checks done before spending a captcha on a row."""
import ipaddress
import re
from urllib.parse import urlsplit

from . import config

SUBMISSION_TYPES = {"domain": "Domain", "ip": "IP", "url": "URL"}
ALLOWED_EXT = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "pdf": "application/pdf"}
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _check_hostname(host: str) -> str | None:
    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return "недопустимые символы в домене"
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or len(labels) < 2:
        return "домен должен иметь вид example.com"
    if not all(_LABEL.match(label) for label in labels):
        return "недопустимые символы в домене"
    if labels[-1].isdigit():
        return "домен должен иметь вид example.com"
    return None


def validate_target(kind: str, value: str) -> str | None:
    """Returns an error message, or None when the value looks fine."""
    value = value.strip()
    if not value:
        return "пустая строка"
    if kind == "domain":
        if "://" in value or "/" in value:
            return "это похоже на URL — для домена укажите только имя, например example.com"
        try:
            ipaddress.ip_address(value)
            return "это IP-адрес — выберите тип IP"
        except ValueError:
            pass
        return _check_hostname(value)
    if kind == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return "неверный IP-адрес"
        return None
    if kind == "url":
        if len(value) > 2000:
            return "URL длиннее 2000 символов"
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https"):
            return "URL должен начинаться с http:// или https://"
        if not parts.hostname:
            return "в URL нет домена"
        try:
            ipaddress.ip_address(parts.hostname)
            return None
        except ValueError:
            return _check_hostname(parts.hostname)
    return f"неизвестный тип: {kind}"


def parse_targets(text: str) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def validate_attachment(filename: str, data: bytes) -> tuple[str | None, str | None]:
    """Returns (error, mime type)."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        return "разрешены только файлы JPG, JPEG, PNG или PDF", None
    if len(data) == 0:
        return "файл пустой", None
    if len(data) > config.MAX_FILE_SIZE:
        return f"файл больше 2 МБ ({len(data) / 1024 / 1024:.2f} МБ)", None
    mime = ALLOWED_EXT[ext]
    signatures = {
        "image/jpeg": data.startswith(b"\xff\xd8\xff"),
        "image/png": data.startswith(b"\x89PNG\r\n\x1a\n"),
        "application/pdf": data.startswith(b"%PDF-"),
    }
    if not signatures[mime]:
        return "содержимое файла не соответствует расширению", None
    return None, mime
