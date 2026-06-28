"""
AnarkisHunter — utils_logger.py
=================================
Automatic file logging ke logs/ directory.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from config.settings import LOGS_DIR


def setup_logger(
    name: str = "anarkishunter",
    level: int = logging.INFO,
    target: str = "",
) -> logging.Logger:
    """
    Setup logger dengan file output ke logs/anarkishunter_YYYYMMDD_HHMMSS.log
    """
    LOGS_DIR.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = target.replace("://", "_").replace("/", "_").replace(":", "_")[:50] if target else "scan"
    log_file = LOGS_DIR / f"anarkishunter_{domain}_{ts}.log"

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    logger.info(f"Log started → {log_file}")
    return logger


def get_logger(name: str = "anarkishunter") -> logging.Logger:
    return logging.getLogger(name)
