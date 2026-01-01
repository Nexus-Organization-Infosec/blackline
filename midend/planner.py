# blackline/midend/planner.py
#
# Semantic planner.
# Converts parsed intent into executable Tasks.

import uuid
from typing import Dict, List

from config.config_loader import load_config


DEFAULTS_PATH = "midend/defaults.json"
ACTION_PATH_TEMPLATE = "midend/{action}.json"


def plan_intent(intent: Dict) -> List[Dict]:
    """
    Convert parsed intent into a list of semantic Tasks.

    Input:
        {
            "action": "recon",
            "entities": {...},
            "operators": [...]
        }

    Output:
        [
            {
                "task_id": "...",
                "action": "...",
                "target": {...},
                "intent": {...},
                "execution": {...}
            }
        ]
    """
    action = intent.get("action")
    if not action:
        return []

    entities = intent.get("entities", {})
    operators = _normalize_operators(intent.get("operators", []))

    # Load action definition 
    action_def = load_config(ACTION_PATH_TEMPLATE.format(action=action))
    if not action_def:
        return []

    # Load semantic defaults for this action
    defaults = load_config(DEFAULTS_PATH).get(action, {})

    supported_entities = action_def.get("supported_entities", [])
    supported_intent = action_def.get("supported_intent", [])

    targets = _resolve_targets(entities, supported_entities)
    if not targets:
        return []

    tasks = []
    for target in targets:
        task = _build_task(
            action=action,
            target=target,
            entities=entities,
            defaults=defaults,
            supported_intent=supported_intent,
            operators=operators,
        )
        tasks.append(task)

    return tasks


def _build_task(
    action: str,
    target: Dict,
    entities: Dict,
    defaults: Dict,
    supported_intent: List[str],
    operators: Dict,
) -> Dict:
    """Build a single semantic Task."""
    intent_data = {}

    for key in supported_intent:
        if key in entities and entities[key]:
            intent_data[key] = entities[key][0]
        elif key in defaults:
            intent_data[key] = defaults[key]

    return {
        "task_id": str(uuid.uuid4()),
        "action": action,
        "target": target,
        "intent": intent_data,
        "execution": {
            "background": operators.get("background", False)
        },
    }


def _resolve_targets(entities: Dict, supported_entities: List[str]) -> List[Dict]:
    """
    Normalize entity targets into a canonical form:
    {
        "type": "...",
        "value": "..."
    }
    """
    targets = []

    for entity_type in supported_entities:
        values = entities.get(entity_type, [])
        for value in values:
            targets.append({
                "type": entity_type,
                "value": value
            })

    return targets


def _normalize_operators(operators) -> Dict[str, bool]:
    """Normalize operators into a simple boolean map."""
    normalized = {}

    if isinstance(operators, list):
        for op in operators:
            name = op.get("name")
            if name:
                normalized[name] = True

    elif isinstance(operators, dict):
        normalized = operators

    return normalized
