# blackline/midend/api.py
#
# Public interface to the midend planner.
# Converts parsed intent into semantic Tasks
# and orchestrates execution with followups.

from typing import Dict, List

from midend.planner import plan_intent, plan_followups
from backend.runner import run_task


def submit_intent(intent: Dict) -> List[Dict]:
    """Submit parsed intent to the planner and execute with followups."""

    if not isinstance(intent, dict):
        return []

    tasks = plan_intent(intent)
    if not isinstance(tasks, list) or not tasks:
        return []

    results = []
    queue = list(tasks)

    while queue:
        task = queue.pop(0)

        result = run_task(task)
        results.append(result)

        # Ask planner if this result triggers followups
        followups = plan_followups(task, result)
        if followups:
            queue.extend(followups)

    return results
