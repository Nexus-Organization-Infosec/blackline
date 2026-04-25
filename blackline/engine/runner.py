"""Engine runner."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable

from blackline.engine.executor import StepResult, execute_plan
from blackline.engine.planner import ExecutionPlan, build_plan
from blackline.engine.state.context import ExecutionContext
from blackline.engine.state.session import EngineSession
from blackline.utils.exec import CommandResult


@dataclass(frozen=True, slots=True)
class RunResult:
    """Top-level engine run result."""

    context: ExecutionContext
    plan: ExecutionPlan
    results: tuple[StepResult, ...]

    @property
    def ok(self) -> bool:
        return all(result.ok for result in self.results)


def run_expression(
    expression: str,
    *,
    session: EngineSession | None = None,
    command_executor: Callable[[tuple[str, ...]], CommandResult] | None = None,
) -> RunResult:
    """Parse, plan, and execute one expression."""
    session = session or EngineSession()
    context = parse_expression(expression, job_id=session.active_job)
    plan = build_plan(context)
    results = execute_plan(plan, command_executor=command_executor)
    session.runs.append(expression)
    return RunResult(context=context, plan=plan, results=results)


def parse_expression(expression: str, *, job_id: str = "") -> ExecutionContext:
    """Parse a module[key=value] expression into execution context."""
    stripped = normalize_expression(expression)
    if not stripped:
        return ExecutionContext(expression=expression, module="", params={}, job_id=job_id)

    if "[" not in stripped:
        return ExecutionContext(expression=expression, module=stripped, params={}, job_id=job_id)

    if not stripped.endswith("]"):
        return ExecutionContext(expression=expression, module=stripped, params={}, job_id=job_id)

    module, raw_params = stripped.split("[", 1)
    params: dict[str, str] = {}
    raw_params = raw_params[:-1].strip()
    if raw_params:
        for pair in raw_params.split(","):
            if "=" not in pair:
                continue
            key, value = pair.split("=", 1)
            params[key.strip()] = value.strip()
    return ExecutionContext(expression=expression, module=module.strip(), params=params, job_id=job_id)


def normalize_expression(expression: str) -> str:
    """Normalize module expressions to be tolerant of spacing and newlines."""
    normalized = " ".join(expression.strip().split())
    normalized = re.sub(r"\s*\[\s*", "[", normalized)
    normalized = re.sub(r"\s*,\s*", ", ", normalized)
    normalized = re.sub(r"\s*=\s*", "=", normalized)
    normalized = re.sub(r"\s*\]\s*", "]", normalized)
    return normalized
