"""Safe capability-based runtime for normalized CLT workflows."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from blackline.clt.errors import CapabilityResolutionError
from blackline.clt.ir import ActionIntent, ConditionIntent, IRAssignment, IRFlow, IROperation, IRRule, IRStatement, WorkflowIR


@dataclass(frozen=True, slots=True)
class CapabilityInvocation:
    """The typed request passed to a registered capability handler."""

    intent: ActionIntent
    inputs: tuple[str, ...] = ()
    options: Mapping[str, str] = field(default_factory=dict)
    variables: Mapping[str, str] = field(default_factory=dict)


CapabilityHandler = Callable[[CapabilityInvocation], Mapping[str, object] | None]


@dataclass(frozen=True, slots=True)
class Capability:
    """One explicit implementation of a CLT action intent."""

    verb: str
    subject: str = ""
    handler: CapabilityHandler | None = None


class CapabilityRegistry:
    """Registry used by Blackline core and plugins to provide CLT actions."""

    def __init__(self) -> None:
        self._capabilities: dict[tuple[str, str], Capability] = {}

    def register(self, verb: str, subject: str = "", handler: CapabilityHandler | None = None) -> None:
        """Register one capability; a duplicate intent is an explicit error."""
        key = (verb.strip().lower(), subject.strip().lower())
        if not key[0]:
            raise ValueError("a CLT capability requires an action verb")
        if key in self._capabilities:
            raise ValueError(f"CLT capability already registered: {key[0]} {key[1]}".rstrip())
        self._capabilities[key] = Capability(*key, handler=handler)

    def resolve(self, intent: ActionIntent) -> Capability | None:
        """Resolve an exact intent, then a verb-wide generic capability."""
        key = (intent.verb.lower(), intent.subject.lower())
        return self._capabilities.get(key) or self._capabilities.get((key[0], ""))


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    """One action considered or executed during a workflow run."""

    intent: ActionIntent
    state: str
    output: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuntimeResult:
    """Deterministic result of a CLT workflow run."""

    variables: Mapping[str, str]
    events: tuple[RuntimeEvent, ...]


class CLTRuntime:
    """Execute IR only through explicitly registered capability handlers."""

    def __init__(self, registry: CapabilityRegistry) -> None:
        self.registry = registry

    def run(self, workflow: WorkflowIR, *, facts: Mapping[object, object] | None = None) -> RuntimeResult:
        """Run a compiled workflow against supplied facts and registered handlers."""
        state = _RuntimeState(facts=dict(facts or {}))
        self._run_block(workflow.statements, state)
        return RuntimeResult(dict(state.variables), tuple(state.events))

    def _run_block(self, statements: tuple[IRStatement, ...], state: _RuntimeState) -> None:
        for statement in statements:
            if isinstance(statement, IRAssignment):
                state.variables[statement.name] = _interpolate(statement.value, state.variables)
            elif isinstance(statement, IROperation):
                self._invoke(statement.intent, statement.inputs, dict(statement.options), state)
                self._run_block(statement.body, state)
            elif isinstance(statement, IRFlow):
                self._invoke(statement.intent, (), {}, state)
            elif isinstance(statement, IRRule):
                if _condition_matches(statement.condition, state.facts):
                    self._run_block(statement.body, state)
                else:
                    self._run_block(statement.else_body, state)
            else:
                raise TypeError(f"unsupported IR statement: {type(statement).__name__}")

    def _invoke(self, intent: ActionIntent, inputs: tuple[str, ...], options: dict[str, str], state: _RuntimeState) -> None:
        capability = self.registry.resolve(intent)
        if capability is None:
            description = f"{intent.verb} {intent.subject}".strip()
            raise CapabilityResolutionError(f"no registered capability can {description}", intent.location)
        invocation = CapabilityInvocation(
            intent=intent,
            inputs=tuple(_interpolate(value, state.variables) for value in inputs),
            options={key: _interpolate(value, state.variables) for key, value in options.items()},
            variables=dict(state.variables),
        )
        output = capability.handler(invocation) if capability.handler else None
        state.events.append(RuntimeEvent(intent, "done", dict(output or {})))


@dataclass(slots=True)
class _RuntimeState:
    facts: dict[object, object]
    variables: dict[str, str] = field(default_factory=dict)
    events: list[RuntimeEvent] = field(default_factory=list)


def _condition_matches(condition: ConditionIntent, facts: Mapping[object, object]) -> bool:
    key = (condition.entity, condition.value)
    if key in facts:
        return str(facts[key]).lower() == condition.state
    dotted = f"{condition.entity}.{condition.value}"
    if dotted in facts:
        return str(facts[dotted]).lower() == condition.state
    return False


def _interpolate(value: str, variables: Mapping[str, str]) -> str:
    return variables.get(value, value)
