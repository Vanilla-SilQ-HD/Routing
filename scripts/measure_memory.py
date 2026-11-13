"""Measure sing-box RSS while loading local rule sets, without inbounds."""
from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from .logging_utils import configure_logging
except ImportError:
    from logging_utils import configure_logging  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger(__name__)


def rss_bytes(process: Any) -> int:
    if os.name == "nt":
        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong)]
            _fields_ += [(name, ctypes.c_size_t) for name in (
                "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                "PagefileUsage", "PeakPagefileUsage")]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            raise OSError("Windows windll is unavailable")
        if not windll.psapi.GetProcessMemoryInfo(
                ctypes.c_void_p(process._handle), ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.WorkingSetSize)
    status = Path(f"/proc/{process.pid}/status").read_text(encoding="utf-8")
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    raise OSError("VmRSS is unavailable")


def measure(executable: Path, rulesets: list[Path], seconds: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="routing-memory-") as temporary:
        config = Path(temporary) / "config.json"
        config.write_text(json.dumps({
            "log": {"level": "warn"},
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {
                "rule_set": [{"type": "local", "tag": f"set-{index}", "format": "binary",
                              "path": str(path.resolve())} for index, path in enumerate(rulesets)],
                "rules": [{"rule_set": [f"set-{index}"], "action": "route", "outbound": "direct"}
                          for index in range(len(rulesets))],
                "final": "direct",
            },
        }), encoding="utf-8")
        process = subprocess.Popen(
            [str(executable), "run", "--config", str(config)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        peak = 0
        started = time.monotonic()
        try:
            while time.monotonic() - started < seconds:
                if process.poll() is not None:
                    error_output = process.stderr.read() if process.stderr is not None else "unknown error"
                    raise RuntimeError("sing-box exited: " + error_output)
                peak = max(peak, rss_bytes(process))
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stderr is not None:
                process.stderr.close()
        return {"max_rss_bytes": peak, "seconds": round(time.monotonic() - started, 2),
                "rule_sets": [{"path": str(path.resolve()), "bytes": path.stat().st_size} for path in rulesets]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ruleset", nargs="+", type=Path)
    parser.add_argument("--sing-box", type=Path)
    parser.add_argument("--seconds", type=float, default=5)
    args = parser.parse_args()
    configure_logging()
    executable = args.sing_box or ROOT / ".tools" / ("sing-box.exe" if os.name == "nt" else "sing-box")
    if not executable.is_file() or any(not path.is_file() for path in args.ruleset) or args.seconds <= 0:
        parser.error("sing-box and every ruleset must exist; seconds must be positive")
    try:
        logger.info(json.dumps(measure(executable.resolve(), args.ruleset, args.seconds), ensure_ascii=False))
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"MEMORY MEASUREMENT FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
