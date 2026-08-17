import os
import re
import sys
import logging
from logging.handlers import RotatingFileHandler
import structlog
from typing import Any
from app.config import settings

# Regex for matching IPv4 and IPv6 addresses (including compressed :: IPv6)
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_REGEX = re.compile(r"(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}")


def pii_scrubber_processor(logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Structlog processor that enforces PII Zero by redacting raw IP addresses
    from any log event message or kwarg dictionary before output.
    """
    def sanitize(value: Any) -> Any:
        if isinstance(value, str):
            value = IPV4_REGEX.sub("[REDACTED_IP]", value)
            value = IPV6_REGEX.sub("[REDACTED_IP]", value)
            return value
        elif isinstance(value, dict):
            return {k: sanitize(v) for k, v in value.items() if k.lower() not in ("ip", "client_ip", "user_ip")}
        elif isinstance(value, list):
            return [sanitize(v) for v in value]
        return value

    # Remove direct 'ip' key if present
    event_dict.pop("ip", None)
    event_dict.pop("client_ip", None)
    event_dict.pop("user_ip", None)

    return sanitize(event_dict)


def setup_logging(debug: bool = False) -> None:
    """Configures structlog for stdout and rotating file logs with strict PII Zero safety."""
    logs_dir = os.path.join(settings.DATA_DIR, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_file_path = os.path.join(logs_dir, "ip_score.log")

    # Rotating File Handler (10 MB max file size, 5 backup rotation retention)
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )

    processors = [
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        pii_scrubber_processor,
        structlog.processors.JSONRenderer()
    ]

    structlog.configure(
        processors=processors,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


logger = structlog.get_logger("ip_score_api")
