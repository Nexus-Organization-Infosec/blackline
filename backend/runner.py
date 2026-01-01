# blackline/backend/runner.py
#
# Backend execution engine.
# Receives semantic Tasks from midend, selects the appropriate
# backend executor, runs it, and returns execution truth.

from typing import Any, Dict

from utils.display import print_error
from config.config_loader import load_config

from backend.recon import nmap as nmap_executor


TOOLS_CONFIG_PATH = "backend/recon/tools.json"


def run_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a semantic Task and return the backend result."""
    if not isinstance(task, dict):
        return _error_result(task, "Invalid task format (expected dict).")

    action = task.get("action")
    if not action:
        return _error_result(task, "Task missing action.")

    # Load tool registry for this action
    tools_cfg = load_config(TOOLS_CONFIG_PATH)
    if not tools_cfg:
        return _error_result(task, "No backend tools configuration found.")

    # Select executor
    executor = _select_executor(task, tools_cfg)
    if not executor:
        return _error_result(task, f"No backend executor available for action '{action}'.")

    try:
        return executor.run(task)
    except Exception as e:
        print_error(f"Backend execution failed: {e}")
        return _error_result(task, f"Backend execution error: {e}")


def _select_executor(task: Dict[str, Any], tools_cfg: Dict[str, Any]):
    """Select an executor based on task semantics and backend tool capabilities."""
    action = task.get("action")
    target = task.get("target", {})
    intent = task.get("intent", {})

    target_type = target.get("type")
    intent_keys = set(intent.keys())

    best_match = None
    best_priority = -1

    for tool_name, tool_def in tools_cfg.items():
        if tool_def.get("action") != action:
            continue

        supported_targets = set(tool_def.get("targets", []))
        if target_type not in supported_targets:
            continue

        supported_intent = set(tool_def.get("supports", []))
        if not intent_keys.issubset(supported_intent):
            continue

        priority = int(tool_def.get("priority", 0))
        if priority > best_priority:
            best_priority = priority
            best_match = tool_name

    # For now, we only have one recon executor
    if best_match == "nmap":
        return nmap_executor

    return None


def _error_result(task: Dict[str, Any], message: str) -> Dict[str, Any]:
    """
    Standardized backend error result.
    """
    return {
        "task_id": task.get("task_id") if isinstance(task, dict) else None,
        "action": task.get("action") if isinstance(task, dict) else None,
        "tool": None,
        "cmd": [],
        "stdout": "",
        "stderr": message,
        "exit_code": -1,
        "duration": 0.0,
        "timed_out": False,
        "data": {},
    }
