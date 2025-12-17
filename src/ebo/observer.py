"""Minimal observer daemon that logs to journald via stdout/stderr."""

from __future__ import annotations

import logging
import signal
import sys
from threading import Event


_shutdown = Event()
_logger = logging.getLogger("ebo.observer")


def _setup_logging() -> None:
    """Send log messages to stdout so systemd can forward them to journald."""
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    _logger.setLevel(logging.INFO)
    _logger.addHandler(handler)
    _logger.propagate = False


def _handle_signal(signum, _frame) -> None:
    try:
        name = signal.Signals(signum).name
    except ValueError:
        name = str(signum)
    _logger.info("ebo-observer received signal %s; shutting down", name)
    _shutdown.set()


def main() -> int:
    _setup_logging()
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _logger.info("ebo-observer starting up")
    _shutdown.wait(timeout=5)
    _logger.info("ebo-observer shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
