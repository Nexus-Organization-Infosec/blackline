# blackline/backend/runner.py
#
# Backend execution engine.
# Receives semantic Tasks from midend, selects the appropriate
# backend executor, runs it, and returns execution truth.

from typing import Any, Dict

from utils.display import print_error, print_debug
from config.config_loader import load_config

# Import available executors
from backend.recon import nmap as nmap_executor
from backend.recon import curl_probe as curl_executor


TOOLS_CONFIG_PATH = "backend/recon/tools.json"


# Map tool names (from tools.json) to their executor modules
EXECUTOR_MAP = {
    "nmap": nmap_executor,
    "curl_probe": curl_executor,
}


def run_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a semantic Task and return the backend result."""

    if not isinstance(task, dict):
        return _error_result(task, "Invalid task format (expected dict).")

    action = task.get("action")
    if not action:
        return _error_result(task, "Task missing action.")

    print_debug(f"Running task action: {action}", task)

    # Load tool registry
    tools_cfg = load_config(TOOLS_CONFIG_PATH)
    if not tools_cfg:
        return _error_result(task, "No backend tools configuration found.")

    # Select executor
    executor = _select_executor(task, tools_cfg)
    if not executor:
        return _error_result(
            task,
            f"No backend executor available for action '{action}'."
        )

    try:
        return executor.run(task)
    except Exception as e:
        print_error(f"Backend execution failed: {e}")
        return _error_result(task, f"Backend execution error: {e}")


def _select_executor(task: Dict[str, Any], tools_cfg: Dict[str, Any]):
    """
    Select an executor based on task semantics and backend tool capabilities.
    """

    action = task.get("action")
    target = task.get("target", {})
    intent = task.get("intent", {})

    target_type = target.get("type")
    intent_keys = set(intent.keys())

    best_match = None
    best_priority = -1

    print_debug("Selecting executor...", task)

    for tool_name, tool_def in tools_cfg.items():

        print_debug(f"Checking tool: {tool_name}", task)

        # Action must match
        if tool_def.get("action") != action:
            print_debug(" -> action mismatch", task)
            continue

        # Target type must be supported
        supported_targets = set(tool_def.get("targets", []))
        if target_type not in supported_targets:
            print_debug(" -> target mismatch", task)
            continue

        # Intent keys must be supported
        supported_intent = set(tool_def.get("supports", []))
        if supported_intent and not intent_keys.issubset(supported_intent):
            print_debug(" -> intent mismatch", task)
            continue

        print_debug(" -> MATCH FOUND", task)

        # Priority comparison
        priority = int(tool_def.get("priority", 0))
        if priority > best_priority:
            best_priority = priority
            best_match = tool_name

    if not best_match:
        print_debug("No matching executor found.", task)
        return None

    print_debug(f"Executor selected: {best_match}", task)

    return EXECUTOR_MAP.get(best_match)


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