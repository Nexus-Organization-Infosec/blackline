# blackline/midend/api.py
#
# Public interface to the midend planner.
# Converts parsed intent into semantic Tasks.


from typing import Dict, List

from midend.planner import plan_intent


def submit_intent(intent: Dict) -> List[Dict]:
    """Submit parsed intent to the planner."""
    if not isinstance(intent, dict):
        return []

    tasks = plan_intent(intent)

    if not isinstance(tasks, list):
        return []

    return tasks
