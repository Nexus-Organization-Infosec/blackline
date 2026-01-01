# blackline/backend/recon/nmap.py
#
# Executes nmap for recon tasks.
# Translates semantic intent (stealth, intensity, ports, discovery)
# into concrete nmap flags and runs the tool.
#
# Returns execution truth: stdout, stderr, exit_code, and structured data.

from typing import Any, Dict, List

from backend.utils.exec import run_command
from backend.recon.nmap_parser import parse_nmap_output
from config.config_loader import load_config


NMAP_CONFIG_PATH = "backend/recon/nmap.json"


def run(task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute an nmap scan from a semantic Task.

    Expected Task shape:
    {
      "task_id": "...",
      "action": "recon",
      "target": {"type": "ip|domain", "value": "..."},
      "intent": {"ports": "...", "stealth": 3, "intensity": 0, "discovery": "auto"},
      "execution": {"background": False}
    }
    """
    intent = task.get("intent", {}) or {}
    target = task.get("target", {}) or {}
    target_value = target.get("value")

    if not target_value:
        return _result(
            task=task,
            exec_result={
                "cmd": [],
                "stdout": "",
                "stderr": "Missing target value for nmap task.",
                "exit_code": -1,
                "duration": 0.0,
                "timed_out": False,
            },
            data={},
        )

    cfg = load_config(NMAP_CONFIG_PATH) or {}

    cmd = _build_cmd(target_value=target_value, intent=intent, cfg=cfg)

    print("[debug] nmap cmd:", cmd)

    exec_result = run_command(
        cmd=cmd,
        timeout=_safe_int(cfg.get("timeout"), default=None),
        cwd=cfg.get("cwd"),
        env=cfg.get("env"),
    )

    # Parse structured data from stdout only if we have any
    data: Dict[str, Any] = {}
    if exec_result.get("stdout"):
        try:
            data = parse_nmap_output(exec_result["stdout"])
        except Exception as e:
            # Parsing failures should not hide execution truth
            data = {"parse_error": str(e)}

    return _result(task=task, exec_result=exec_result, data=data)


def _build_cmd(target_value: str, intent: Dict[str, Any], cfg: Dict[str, Any]) -> List[str]:
    """
    Build a safe argv list for nmap.

    Notes:
    - We never pass "top1000" as a literal port list to -p.
      If ports == "top1000", we translate to: --top-ports 1000
    - All mappings here are backend owned (tool-specific).
    """
    cmd: List[str] = [cfg.get("binary", "nmap")]

    # discovery policy 
    discovery = str(intent.get("discovery", "auto"))
    if discovery == "force":
        # Scan even if host discovery would fail
        cmd.append("-Pn")
    elif discovery == "skip":
        # "skip discovery" is effectively the same behavior as force for nmap
        cmd.append("-Pn")

    #  stealth -> timing template (-T0..-T5) 
    stealth = intent.get("stealth", None)
    if stealth is not None:
        s = _safe_int(stealth, default=None)
        if s is not None:
            s = max(0, min(5, s))
            cmd.append(f"-T{s}")

    # intensity (semantic depth) 
    # intensity is semantic; map to common nmap behaviors.
    # Keep it conservative by default.
    intensity = _safe_int(intent.get("intensity", 0), default=0)
    if intensity >= 3:
        # Service/version detection
        cmd.append("-sV")
    if intensity >= 4:
        # Default scripts (can be noisy; still controlled by intensity)
        cmd.append("-sC")

    ports = intent.get("ports", None)
    if ports:
        ports_str = str(ports).strip().lower()

        # allow configured aliases/mappings
        port_aliases = (cfg.get("ports") or {}) if isinstance(cfg.get("ports"), dict) else {}

        # common built in alias
        if ports_str == "top1000":
            cmd.extend(["--top-ports", "1000"])
        elif ports_str == "common":
            cmd.extend(["--top-ports", "100"])
        elif ports_str in port_aliases:
            # config driven alias expansion (expects list of args)
            mapped = port_aliases[ports_str]
            if isinstance(mapped, list) and all(isinstance(x, str) for x in mapped):
                cmd.extend(mapped)
            else:
                # fall back to safest behavior: treat as raw -p if string like
                cmd.extend(["-p", str(ports)])
        else:
            # raw nmap -p value (ranges/list/ single)
            cmd.extend(["-p", str(ports)])

    # any extra args from config (backend-only)
    extra_args = cfg.get("extra_args", [])
    if isinstance(extra_args, list) and all(isinstance(x, str) for x in extra_args):
        cmd.extend(extra_args)

    # Target last
    cmd.append(str(target_value))

    return cmd


def _result(task: Dict[str, Any], exec_result: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Standard backend response envelope for a tool run.
    Frontend can decide what to display.
    """
    return {
        "task_id": task.get("task_id"),
        "action": task.get("action"),
        "tool": "nmap",
        "cmd": exec_result.get("cmd", []),
        "stdout": exec_result.get("stdout", ""),
        "stderr": exec_result.get("stderr", ""),
        "exit_code": exec_result.get("exit_code", -1),
        "duration": exec_result.get("duration", 0.0),
        "timed_out": exec_result.get("timed_out", False),
        "data": data or {},
    }


def _safe_int(value: Any, default=None):
    try:
        if value is None:
            return default
        return int(value)
    except (ValueError, TypeError):
        return default
