# Vector v0

Vector is Blackline's internal deterministic adaptive planning system. It is not a shell command and does not replace the existing execution engine.

The first implementation proves one decision cycle:

```text
structured observation
    -> incremental state update
    -> capability resolution
    -> candidate creation and deduplication
    -> policy filtering
    -> explainable selection
```

```python
from blackline.clt.ir import ConditionIntent
from blackline.vector import Capability, Goal, Observation, Vector

vector = Vector(Goal("recon", "127.0.0.1", strategy="balanced"))
vector.register_capability(
    Capability.for_action(
        "inspect",
        "ssh",
        requires=(ConditionIntent("service", "ssh", "open"),),
    )
)

decision = vector.observe([
    Observation.service(
        host="127.0.0.1",
        port=22,
        protocol="ssh",
        state="open",
        source="nmap",
        confidence=0.98,
    )
])

candidate = decision.selected[0]
assert candidate.intent.subject == "ssh"
assert candidate.target == "127.0.0.1:22"
```

`Decision` retains selected, rejected, and ranked candidates along with their reasons and observation sources. `Vector.mark_completed()` records an action identity so equivalent work is not proposed again.

This v0 intentionally does not contain a scheduler, executor bridge, graph database, network fan-out, or protocol-specific planning branches. Those responsibilities will be added only after this state-to-decision model is exercised against real Blackline capability output.
