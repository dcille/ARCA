"""Scan execution logger.

Tracks which Python modules were executed and what cloud API calls were made
during a scan, producing a structured JSON log for post-scan review.
"""

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class LogEntry:
    """A single step in the scan execution log."""

    step: int = 0
    timestamp: str = ""
    event: str = ""          # module_start, module_end, api_call, phase_start, phase_end, error
    module: str = ""         # Python module/file that executed
    detail: str = ""         # Human-readable description
    duration_ms: Optional[float] = None
    api_service: str = ""    # e.g. "iam", "s3", "ec2", "storage"
    api_call: str = ""       # e.g. "get_account_summary", "list_buckets"
    result_count: int = 0    # Number of results/findings produced
    status: str = ""         # success, error, skipped


class ScanLogger:
    """Collects execution trace during a scan.

    Usage::

        logger = ScanLogger()
        logger.log_phase_start("service_checks", "aws_scanner.py")
        logger.log_api_call("iam", "get_account_summary", module="aws_scanner.py")
        logger.log_phase_end("service_checks", "aws_scanner.py", result_count=15)
        log_json = logger.to_json()
    """

    def __init__(self) -> None:
        self._entries: list[LogEntry] = []
        self._step = 0
        self._timers: dict[str, float] = {}
        self._scan_start = time.monotonic()
        self._api_call_count = 0

    def _next_step(self) -> int:
        self._step += 1
        return self._step

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def log_phase_start(self, phase: str, module: str = "") -> None:
        """Log the start of a scan phase (e.g. service_checks, cis_engine)."""
        self._timers[phase] = time.monotonic()
        self._entries.append(LogEntry(
            step=self._next_step(),
            timestamp=self._now(),
            event="phase_start",
            module=module,
            detail=f"Starting phase: {phase}",
            status="running",
        ))

    def log_phase_end(
        self, phase: str, module: str = "", result_count: int = 0, status: str = "success"
    ) -> None:
        """Log the end of a scan phase."""
        t0 = self._timers.pop(phase, self._scan_start)
        duration = round((time.monotonic() - t0) * 1000, 1)
        self._entries.append(LogEntry(
            step=self._next_step(),
            timestamp=self._now(),
            event="phase_end",
            module=module,
            detail=f"Completed phase: {phase} ({result_count} results)",
            duration_ms=duration,
            result_count=result_count,
            status=status,
        ))

    def log_module_start(self, module: str, detail: str = "") -> None:
        """Log that a Python module/check group started executing."""
        self._timers[module] = time.monotonic()
        self._entries.append(LogEntry(
            step=self._next_step(),
            timestamp=self._now(),
            event="module_start",
            module=module,
            detail=detail or f"Executing: {module}",
            status="running",
        ))

    def log_module_end(
        self, module: str, result_count: int = 0, status: str = "success", detail: str = ""
    ) -> None:
        """Log that a Python module/check group finished."""
        t0 = self._timers.pop(module, self._scan_start)
        duration = round((time.monotonic() - t0) * 1000, 1)
        self._entries.append(LogEntry(
            step=self._next_step(),
            timestamp=self._now(),
            event="module_end",
            module=module,
            detail=detail or f"Finished: {module} ({result_count} results)",
            duration_ms=duration,
            result_count=result_count,
            status=status,
        ))

    def log_api_call(
        self,
        service: str,
        call: str,
        module: str = "",
        status: str = "success",
        detail: str = "",
    ) -> None:
        """Log a cloud API call."""
        self._api_call_count += 1
        self._entries.append(LogEntry(
            step=self._next_step(),
            timestamp=self._now(),
            event="api_call",
            module=module,
            api_service=service,
            api_call=call,
            detail=detail or f"API: {service}.{call}()",
            status=status,
        ))

    def log_error(self, module: str, detail: str) -> None:
        """Log an error during execution."""
        self._entries.append(LogEntry(
            step=self._next_step(),
            timestamp=self._now(),
            event="error",
            module=module,
            detail=detail,
            status="error",
        ))

    @property
    def api_call_count(self) -> int:
        return self._api_call_count

    @property
    def entries(self) -> list[LogEntry]:
        return list(self._entries)

    def get_summary(self) -> dict:
        """Return a summary of the scan execution."""
        total_duration = round((time.monotonic() - self._scan_start) * 1000, 1)
        modules_executed = sorted({
            e.module for e in self._entries
            if e.event == "module_end" and e.module
        })
        api_calls = [
            {"service": e.api_service, "call": e.api_call, "status": e.status}
            for e in self._entries
            if e.event == "api_call"
        ]
        phases = [
            {"phase": e.detail.replace("Completed phase: ", "").split(" (")[0],
             "duration_ms": e.duration_ms, "results": e.result_count}
            for e in self._entries
            if e.event == "phase_end"
        ]
        errors = [
            {"module": e.module, "detail": e.detail}
            for e in self._entries
            if e.event == "error"
        ]

        return {
            "total_duration_ms": total_duration,
            "total_steps": self._step,
            "total_api_calls": self._api_call_count,
            "modules_executed": modules_executed,
            "phases": phases,
            "api_calls_summary": api_calls,
            "errors": errors,
        }

    def to_dict(self) -> dict:
        """Return the full log as a serialisable dict."""
        return {
            "summary": self.get_summary(),
            "entries": [asdict(e) for e in self._entries],
        }

    def to_json(self) -> str:
        """Serialise the full log to JSON."""
        return json.dumps(self.to_dict(), default=str)
