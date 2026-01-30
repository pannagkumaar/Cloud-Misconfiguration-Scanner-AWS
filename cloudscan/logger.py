"""
Logging configuration for Cloud Misconfiguration Scanner.

Provides consistent logging across all modules.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configure logging for the scanner.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to write logs to

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("cloudscan")
    logger.setLevel(getattr(logging, log_level.upper()))

    # Remove any existing handlers
    logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, log_level.upper()))

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger for a specific module."""
    return logging.getLogger(f"cloudscan.{name}")
