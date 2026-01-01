# blackline/backend/utils/exec.py

from __future__ import annotations

import subprocess
import time
from typing import Any, Dict, List, Optional


def run_command(
    cmd: List[str],
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Execute a command safely and return a normalized result dict."""
    start = time.time()

    if not isinstance(cmd, list) or not all(isinstance(x, str) for x in cmd):
        return {
            "cmd": cmd,
            "stdout": "",
            "stderr": "Invalid command format: cmd must be a list[str].",
            "exit_code": -1,
            "duration": time.time() - start,
            "timed_out": False,
        }

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )

        return {
            "cmd": cmd,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "exit_code": int(proc.returncode),
            "duration": time.time() - start,
            "timed_out": False,
        }

    except subprocess.TimeoutExpired as e:
        stdout = ""
        stderr = ""
        if getattr(e, "stdout", None):
            stdout = e.stdout if isinstance(e.stdout, str) else e.stdout.decode(errors="replace")
        if getattr(e, "stderr", None):
            stderr = e.stderr if isinstance(e.stderr, str) else e.stderr.decode(errors="replace")

        return {
            "cmd": cmd,
            "stdout": stdout or "",
            "stderr": (stderr or "") + ("\n[blackline] command timed out." if stderr else "[blackline] command timed out."),
            "exit_code": -1,
            "duration": time.time() - start,
            "timed_out": True,
        }

    except FileNotFoundError:
        return {
            "cmd": cmd,
            "stdout": "",
            "stderr": f"Command not found: {cmd[0]}",
            "exit_code": -1,
            "duration": time.time() - start,
            "timed_out": False,
        }

    except Exception as e:
        return {
            "cmd": cmd,
            "stdout": "",
            "stderr": f"Execution failed: {e}",
            "exit_code": -1,
            "duration": time.time() - start,
            "timed_out": False,
        }
