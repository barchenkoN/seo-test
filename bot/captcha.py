"""2captcha client (API v2: createTask / getTaskResult)."""
import time

import requests

from . import config


class CaptchaError(Exception):
    """Captcha could not be solved. `fatal` means retrying will not help (bad key, no balance)."""

    def __init__(self, message: str, fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


FATAL_CODES = {
    "ERROR_KEY_DOES_NOT_EXIST": "неверный ключ 2captcha",
    "ERROR_WRONG_USER_KEY": "неверный формат ключа 2captcha",
    "ERROR_ZERO_BALANCE": "на счёте 2captcha закончились деньги",
    "ERROR_IP_NOT_ALLOWED": "IP не разрешён в настройках 2captcha",
    "ERROR_IP_BANNED": "IP заблокирован 2captcha",
}
MESSAGES = {
    "ERROR_NO_SLOT_AVAILABLE": "2captcha перегружен, нет свободных работников",
    "ERROR_CAPTCHA_UNSOLVABLE": "2captcha не смог решить капчу",
    "ERROR_GOOGLEKEY": "2captcha не принял sitekey reCAPTCHA",
    "ERROR_PAGEURL": "2captcha не принял адрес страницы",
}


class TwoCaptcha:
    def __init__(self, api_key: str, api_url: str = config.TWOCAPTCHA_API_URL,
                 timeout: int = config.CAPTCHA_TIMEOUT, poll_interval: float = config.CAPTCHA_POLL_INTERVAL):
        self.api_key = api_key
        self.api_url = api_url
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.http = requests.Session()

    def _call(self, method: str, payload: dict) -> dict:
        try:
            resp = self.http.post(f"{self.api_url}/{method}", json={"clientKey": self.api_key, **payload},
                                  timeout=config.HTTP_TIMEOUT)
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise CaptchaError(f"нет связи с 2captcha: {exc}") from exc
        if data.get("errorId"):
            code = data.get("errorCode", "UNKNOWN")
            if code in FATAL_CODES:
                raise CaptchaError(f"{FATAL_CODES[code]} ({code})", fatal=True)
            text = MESSAGES.get(code) or data.get("errorDescription") or "ошибка 2captcha"
            raise CaptchaError(f"{text} ({code})")
        return data

    def balance(self) -> float:
        if not self.api_key:
            raise CaptchaError("ключ не задан", fatal=True)
        return float(self._call("getBalance", {}).get("balance", 0))

    def solve_recaptcha_v2(self, site_key: str, page_url: str, user_agent: str | None = None) -> tuple[str, int]:
        """Returns (g-recaptcha-response token, task id)."""
        if not self.api_key:
            raise CaptchaError("не задан ключ 2captcha (TWOCAPTCHA_API_KEY)", fatal=True)
        task = {"type": "RecaptchaV2TaskProxyless", "websiteURL": page_url, "websiteKey": site_key}
        if user_agent:
            task["userAgent"] = user_agent
        task_id = self._call("createTask", {"task": task})["taskId"]

        deadline = time.monotonic() + self.timeout
        time.sleep(min(self.poll_interval * 2, 10))  # reCAPTCHA is practically never solved in under 10 s
        while True:
            data = self._call("getTaskResult", {"taskId": task_id})
            if data.get("status") == "ready":
                token = (data.get("solution") or {}).get("gRecaptchaResponse")
                if not token:
                    raise CaptchaError("2captcha вернул пустое решение")
                return token, task_id
            if time.monotonic() > deadline:
                raise CaptchaError(f"капча не решена за {self.timeout} с")
            time.sleep(self.poll_interval)

    def report_bad(self, task_id: int) -> None:
        """Tell 2captcha the token was rejected (refund + better workers). Best effort."""
        try:
            self._call("reportIncorrect", {"taskId": task_id})
        except CaptchaError:
            pass
