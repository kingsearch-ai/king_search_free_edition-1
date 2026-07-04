"""Shared utilities for King Search modules.

Centralizes cross-cutting boilerplate that was previously duplicated across the
individual modules: user-agent rotation, logging configuration, colored console
output, SSL warning suppression and simple file loading.
"""

import logging
import random

try:
    from colorama import init as _colorama_init
    _COLORAMA_AVAILABLE = True
except ImportError:  # colorama is optional
    _COLORAMA_AVAILABLE = False


# A pool of realistic browser user agents used to reduce fingerprinting during
# authorized security testing.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.80 Mobile/15E148 Safari/604.1",
]

DEFAULT_USER_AGENT = USER_AGENTS[0]


def get_random_user_agent():
    """Return a random user agent from :data:`USER_AGENTS`."""
    return random.choice(USER_AGENTS)


DEFAULT_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class ColoredFormatter(logging.Formatter):
    """Logging formatter that colorizes the level name for terminal output."""

    COLORS = {
        'DEBUG': '\033[94m',            # Blue
        'INFO': '\033[92m',             # Green
        'WARNING': '\033[93m',          # Yellow
        'ERROR': '\033[91m',            # Red
        'CRITICAL': '\033[91m\033[1m',  # Bold Red
        'ENDC': '\033[0m',              # Reset
    }

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['ENDC']}"
        return super().format(record)


def configure_logging(level=logging.INFO, log_file=None, fmt=DEFAULT_LOG_FORMAT,
                      datefmt=None, logger_name=None):
    """Configure the root logger with a stream handler and optional file handler.

    Returns the named logger (or the root logger when ``logger_name`` is None).
    """
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.insert(0, logging.FileHandler(log_file))
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, handlers=handlers)
    return logging.getLogger(logger_name)


def setup_colored_logging(level=logging.INFO, fmt=DEFAULT_LOG_FORMAT,
                          datefmt=DEFAULT_DATE_FORMAT):
    """Attach a :class:`ColoredFormatter` stream handler to the root logger."""
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter(fmt, datefmt=datefmt))
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def init_colorama(autoreset=False):
    """Initialize colorama for cross-platform colored output, when available."""
    if _COLORAMA_AVAILABLE:
        _colorama_init(autoreset=autoreset)


def disable_ssl_warnings():
    """Suppress urllib3 insecure-request warnings (self-signed certs during testing)."""
    import requests
    try:
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except Exception:
        requests.packages.urllib3.disable_warnings()


def load_lines(file_path):
    """Read a text file and return a list of stripped, non-empty lines."""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]
