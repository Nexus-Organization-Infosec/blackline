# blackline/backend/recon/curl_probe.py
#
# Executes curl for HTTP service validation.
# Translates semantic intent (protocol, port)
# into concrete curl flags and runs the tool.
#
# Returns execution truth: stdout, stderr, exit_code, and structured data.

from typing import Any, Dict, List

from backend.utils.exec import run_command
from backend.recon.curl_probe_parser import parse_curl_headers
from config.config_loader import load_config
from utils.display import print_debug


CURL_CONFIG_PATH = "backend/recon/curl_probe.json"


def run(task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a curl probe from a semantic Task.

    Expected Task shape:
    {
      "task_id": "...",
      "action": "curl_probe",
      "target": {"type": "ip|domain|url", "value": "..."},
      "intent": {"protocol": "http|https", "port": 80},
      "execution": {"background": False}
    }
    """

    intent = task.get("intent", {}) or {}
    target = task.get("target", {}) or {}
    target_value = target.get("value")

    if not target_value:
        return _result(
            task=task,
            exec_result=_error_exec("Missing target value for curl task."),
            data={},
        )

    cfg = load_config(CURL_CONFIG_PATH) or {}

    protocol = str(intent.get("protocol", "http")).lower()
    port = intent.get("port")

    url = _build_url(protocol, target_value, port)

    cmd = _build_cmd(url=url, cfg=cfg)

    print_debug(f"curl cmd: {cmd}", task)

    exec_result = run_command(
        cmd=cmd,
        timeout=_safe_int(cfg.get("timeout"), default=None),
        cwd=cfg.get("cwd"),
        env=cfg.get("env"),
    )

    data: Dict[str, Any] = {}

    if exec_result.get("stdout"):
        try:
            parsed = parse_curl_headers(exec_result["stdout"])
            parsed["protocol"] = protocol
            parsed["port"] = port
            parsed["url"] = url
            data = parsed
        except Exception as e:
            data = {"parse_error": str(e)}

    return _result(task=task, exec_result=exec_result, data=data)


def _build_url(protocol: str, target: str, port: Any) -> str:
    """
    Build a proper URL string.
    """
    if port:
        return f"{protocol}://{target}:{port}"
    return f"{protocol}://{target}"


def _build_cmd(url: str, cfg: Dict[str, Any]) -> List[str]:
    """
    Build curl argv list safely.
    """
    cmd: List[str] = [cfg.get("binary", "curl")]

    default_args = cfg.get("default_args", ["-s", "-k", "-I"])
    if isinstance(default_args, list) and all(isinstance(x, str) for x in default_args):
        cmd.extend(default_args)

    cmd.append(url)

    return cmd


def _result(task: Dict[str, Any], exec_result: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Standard backend response envelope.
    Matches nmap structure for consistency.
    """
    return {
        "task_id": task.get("task_id"),
        "action": task.get("action"),
        "tool": "curl_probe",
        "cmd": exec_result.get("cmd", []),
        "stdout": exec_result.get("stdout", ""),
        "stderr": exec_result.get("stderr", ""),
        "exit_code": exec_result.get("exit_code", -1),
        "duration": exec_result.get("duration", 0.0),
        "timed_out": exec_result.get("timed_out", False),
        "data": data or {},
    }


def _error_exec(message: str) -> Dict[str, Any]:
    return {
        "cmd": [],
        "stdout": "",
        "stderr": message,
        "exit_code": -1,
        "duration": 0.0,
        "timed_out": False,
    }


def _safe_int(value: Any, default=None):
    try:
        if value is None:
            return default
        return int(value)
    except (ValueError, TypeError):
        return default
