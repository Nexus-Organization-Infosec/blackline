import uuid

from config.config_loader import load_config


def plan_intent(intent: dict) -> list:
    action = intent.get("action")
    if not action:
        return []

    if action == "recon":
        return _plan_recon(intent)

    return []


def _plan_recon(intent: dict) -> list:
    tasks = []

    entities = intent.get("entities", {})
    operators = intent.get("operators", [])

    # execution hints from operators
    background = any(op.get("symbol") == "&" for op in operators)

    # load midend configuration
    recon_cfg = load_config("midend/recon.json") or {}
    mappings = load_config("midend/mappings.json") or {}
    defaults = load_config("midend/defaults.json") or {}

    tool_map = mappings.get("recon", {})
    default_opts = defaults.get("recon", {})

    for entity_type, values in entities.items():
        tools = tool_map.get(entity_type, [])

        for value in values:
            for tool in tools:
                task = {
                    "task_id": str(uuid.uuid4()),
                    "task_type": "recon",
                    "tool": tool,
                    "target": {
                        "type": entity_type,
                        "value": value
                    },
                    "options": default_opts.get(tool, {}).copy(),
                    "execution": {
                        "background": background
                    }
                }

                tasks.append(task)

    return tasks
