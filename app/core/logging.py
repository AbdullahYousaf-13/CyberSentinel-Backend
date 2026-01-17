import logging
from typing import Optional

from app.core.config import Settings


class ContextFilter(logging.Filter):
    def __init__(self, app_env: str) -> None:
        super().__init__()
        self._app_env = app_env

    def filter(self, record: logging.LogRecord) -> bool:
        record.app_env = self._app_env
        return True


def configure_logging(settings: Settings) -> None:
    level = logging.DEBUG if (settings.debug_mode or settings.detailed_logging) else logging.INFO
    format_detail = (
        "%(asctime)s %(levelname)s %(app_env)s %(name)s "
        "%(funcName)s:%(lineno)d %(message)s"
    )
    format_basic = "%(asctime)s %(levelname)s %(app_env)s %(name)s %(message)s"
    logging.basicConfig(level=level, format=format_detail if level == logging.DEBUG else format_basic)
    root_logger = logging.getLogger()
    root_logger.addFilter(ContextFilter(settings.app_env))

    # Reduce noisy third-party logs in normal mode.
    if level != logging.DEBUG:
        for noisy_logger in ("aiokafka", "uvicorn", "motor"):
            logging.getLogger(noisy_logger).setLevel(logging.WARNING)
