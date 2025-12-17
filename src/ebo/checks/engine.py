from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from time import monotonic
from typing import Iterable


class Result(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    WARN = "WARN"


@dataclass
class Check:
    name: str
    prerequisites: list[str] = field(default_factory=list)
    deadline_seconds: float = 0.0
    state: str = "pending"
    armed_at: float | None = None
    result: Result | None = None
    reason: str | None = None

    def arm(self, now: float) -> None:
        if self.state != "pending":
            return
        self.state = "armed"
        self.armed_at = now

    def resolve(self, result: Result, reason: str) -> None:
        if self.result is not None:
            return
        self.result = result
        self.reason = reason
        self.state = "resolved"

    def is_expired(self, now: float) -> bool:
        if self.state != "armed" or not self.deadline_seconds or self.armed_at is None:
            return False
        return now - self.armed_at >= self.deadline_seconds


class Engine:
    def __init__(self, logger: logging.Logger, timeout_seconds: float | None = None) -> None:
        self._logger = logger
        self._checks: dict[str, Check] = {}
        self._events: set[str] = set()
        self._timeout_seconds = timeout_seconds
        self._started_at = monotonic()

    def register(self, check: Check) -> None:
        if check.name in self._checks:
            raise ValueError(f"Duplicate check registration: {check.name}")
        self._checks[check.name] = check
        self._try_arm(check)

    def emit_event(self, event: str) -> None:
        self._events.add(event)
        for check in self._checks.values():
            self._try_arm(check)

    def resolve(self, name: str, result: Result, reason: str) -> Result:
        check = self._checks.get(name)
        if not check:
            raise KeyError(f"Unknown check {name}")
        if check.result is not None:
            return check.result
        check.resolve(result, reason)
        self._log_result(check)
        return result

    def enforce_deadlines(self) -> None:
        now = monotonic()
        for check in self._checks.values():
            if check.result is not None:
                continue
            if check.is_expired(now):
                self.resolve(check.name, Result.FAIL, "deadline expired")

    def finalize(self) -> None:
        now = monotonic()
        for check in self._checks.values():
            if check.result is not None:
                continue
            if check.state != "armed":
                self.resolve(check.name, Result.SKIP, "prerequisites not met before timeout")
                continue
            if check.is_expired(now):
                self.resolve(check.name, Result.FAIL, "deadline expired before timeout")
            else:
                self.resolve(check.name, Result.FAIL, "global timeout before completion")

    def summary(self) -> tuple[dict[Result, int], list[str]]:
        counts: dict[Result, int] = {result: 0 for result in Result}
        failed_checks: list[str] = []
        for check in self._checks.values():
            if check.result is None:
                continue
            counts[check.result] = counts.get(check.result, 0) + 1
            if check.result is Result.FAIL:
                failed_checks.append(check.name)
        return counts, failed_checks

    def _try_arm(self, check: Check) -> None:
        if check.state != "pending":
            return
        if not self._prerequisites_met(check.prerequisites):
            return
        check.arm(monotonic())

    def _prerequisites_met(self, prerequisites: Iterable[str]) -> bool:
        return all(prereq in self._events for prereq in prerequisites)

    def _log_result(self, check: Check) -> None:
        reason = check.reason or ""
        rendered = check.result.value if check.result else ""
        self._logger.info("CHECK=%s RESULT=%s REASON=%s", check.name, rendered, reason)
