from midend.planner import plan_intent


def submit_intent(intent: dict) -> dict:
    """
    Entry point for workflow requests from the frontend.
    """

    if not isinstance(intent, dict):
        return {
            "status": "error",
            "errors": ["Invalid intent object"]
        }

    if intent.get("errors"):
        return {
            "status": "error",
            "errors": intent["errors"]
        }

    try:
        tasks = plan_intent(intent)
    except Exception as e:
        return {
            "status": "error",
            "errors": [str(e)]
        }

    return {
        "status": "ok",
        "tasks": tasks
    }
