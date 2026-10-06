"""Bounded, dependency-aware scheduling for execution plans."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextvars import copy_context
from dataclasses import dataclass, field
from threading import Event
from typing import Callable

from blackline.core.artifacts import ArtifactStore
from blackline.core.recon.outcomes import FAILED, SKIPPED
from blackline.engine.events import EventEmitter, result_event_data, step_event_data
from blackline.engine.graph import dependency_waves
from blackline.engine.models import ExecutionPlan, PlanStep, StepResult

StepExecutor = Callable[[PlanStep, ArtifactStore], StepResult]


@dataclass(frozen=True, slots=True)
class SchedulerOptions:
    """Execution limits shared by every plan run."""

    max_concurrency: int = 4

    def __post_init__(self) -> None:
        if self.max_concurrency < 1:
            raise ValueError("scheduler max_concurrency must be at least 1")


@dataclass(frozen=True, slots=True)
class ExecutionProgress:
    """Legacy lifecycle update retained for UI compatibility."""

    state: str
    completed: int
    total: int
    step: PlanStep
    result: StepResult | None = None


@dataclass(slots=True)
class ExecutionControl:
    """Thread-safe cooperative cancellation state for one run."""

    cancelled: bool = False
    cancellation_reason: str = ""
    _event: Event = field(default_factory=Event, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.cancelled:
            self._event.set()

    def cancel(self, reason: str = "recon cancelled by user") -> None:
        self.cancelled = True
        self.cancellation_reason = reason
        self._event.set()

    def wait(self, seconds: float) -> bool:
        """Wait for backoff, returning true when cancellation interrupts it."""
        return self._event.wait(seconds)


def schedule_plan(
    plan: ExecutionPlan,
    execute_step: StepExecutor,
    *,
    control: ExecutionControl,
    artifact_store: ArtifactStore,
    emitter: EventEmitter,
    options: SchedulerOptions,
    progress_callback: Callable[[ExecutionProgress], None] | None = None,
) -> tuple[StepResult, ...]:
    """Run a validated plan in stable waves with bounded parallelism."""
    indexed_steps = tuple(enumerate(plan.steps))
    result_slots: list[StepResult | None] = [None] * len(indexed_steps)
    outcomes: dict[str, StepResult] = {}
    completed = 0
    if emitter.enabled:
        emitter.emit("plan.started", data={"plan": plan.to_dict(), "total_steps": len(plan.steps)})

    for group in _plan_step_groups(indexed_steps):
        if control.cancelled:
            break
        runnable: list[tuple[int, PlanStep]] = []
        for index, step in group:
            skipped = _dependency_skip(step, outcomes, artifact_store)
            if skipped is not None:
                result_slots[index] = skipped
                outcomes[step.identity] = skipped
                completed += 1
                emitter.emit(
                    "step.skipped",
                    step_id=step.identity,
                    data=result_event_data(skipped, attempt=0, step=step.to_dict()),
                )
                _emit_progress(progress_callback, "completed", completed, len(plan.steps), step, skipped)
                continue
            emitter.emit("step.queued", step_id=step.identity, data=step_event_data(step))
            runnable.append((index, step))

        wave_results = _run_wave(
            tuple(runnable),
            execute_step=execute_step,
            artifact_store=artifact_store.snapshot(),
            control=control,
            emitter=emitter,
            options=options,
            progress_callback=progress_callback,
            completed=completed,
            total=len(plan.steps),
        )
        for index, result in sorted(wave_results, key=lambda item: item[0]):
            result_slots[index] = result
            outcomes[plan.steps[index].identity] = result
            for artifact in result.artifacts:
                if artifact_store.add(artifact):
                    emitter.emit(
                        "artifact.created",
                        step_id=plan.steps[index].identity,
                        data={"artifact": artifact.to_dict()},
                    )
            completed += 1
            _emit_progress(progress_callback, "completed", completed, len(plan.steps), plan.steps[index], result)

    if control.cancelled:
        emitter.emit("plan.cancelled", data={"reason": control.cancellation_reason, "completed_steps": completed})
    emitter.emit(
        "plan.completed",
        data={"completed_steps": completed, "total_steps": len(plan.steps), "cancelled": control.cancelled},
    )
    return tuple(result for result in result_slots if result is not None)


def _run_wave(
    steps: tuple[tuple[int, PlanStep], ...],
    *,
    execute_step: StepExecutor,
    artifact_store: ArtifactStore,
    control: ExecutionControl,
    emitter: EventEmitter,
    options: SchedulerOptions,
    progress_callback: Callable[[ExecutionProgress], None] | None,
    completed: int,
    total: int,
) -> list[tuple[int, StepResult]]:
    if not steps:
        return []
    pending = list(steps)
    running: dict[Future[StepResult], tuple[int, PlanStep]] = {}
    results: list[tuple[int, StepResult]] = []
    interrupted = False
    pool = ThreadPoolExecutor(max_workers=min(options.max_concurrency, len(steps)))
    try:
        while pending or running:
            while pending and len(running) < options.max_concurrency and not control.cancelled:
                index, step = pending.pop(0)
                future = pool.submit(
                    copy_context().run,
                    _execute_with_retries,
                    step,
                    artifact_store.snapshot(),
                    execute_step,
                    control,
                    emitter,
                    progress_callback,
                    completed + len(results),
                    total,
                )
                running[future] = (index, step)
            if not running:
                break
            done, _ = wait(tuple(running), return_when=FIRST_COMPLETED)
            for future in done:
                index, step = running.pop(future)
                try:
                    results.append((index, future.result()))
                except KeyboardInterrupt:
                    interrupted = True
                    control.cancel()
                except Exception as exc:
                    results.append((index, StepResult(step.tool, step.action, False, {}, str(exc))))
    except KeyboardInterrupt:
        interrupted = True
        control.cancel()
    finally:
        if control.cancelled:
            for future in running:
                future.cancel()
        pool.shutdown(wait=True, cancel_futures=True)
    return [] if interrupted else results


def _execute_with_retries(
    step: PlanStep,
    artifacts: ArtifactStore,
    execute_step: StepExecutor,
    control: ExecutionControl,
    emitter: EventEmitter,
    progress_callback: Callable[[ExecutionProgress], None] | None,
    completed: int,
    total: int,
) -> StepResult:
    policy = step.retry_policy
    for attempt in range(1, policy.max_attempts + 1):
        if control.cancelled:
            result = _skipped(step, control.cancellation_reason or "execution cancelled")
            emitter.emit(
                "step.skipped",
                step_id=step.identity,
                data=result_event_data(result, attempt=attempt, step=step.to_dict()),
            )
            return result
        emitter.emit("step.started", step_id=step.identity, data=step_event_data(step, attempt=attempt))
        if attempt == 1:
            _emit_progress(progress_callback, "started", completed, total, step)
        try:
            result = execute_step(step, artifacts)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            result = StepResult(step.tool, step.action, False, {}, str(exc), outcome=FAILED)
        can_retry = attempt < policy.max_attempts and result.outcome in policy.retryable_outcomes
        if not can_retry:
            kind = "step.skipped" if result.outcome == "skipped" else ("step.completed" if result.ok else "step.failed")
            emitter.emit(
                kind,
                step_id=step.identity,
                data=result_event_data(result, attempt=attempt, step=step.to_dict()),
            )
            return result
        emitter.emit(
            "step.retrying",
            step_id=step.identity,
            data=result_event_data(
                result,
                attempt=attempt,
                next_attempt=attempt + 1,
                backoff_seconds=policy.backoff_seconds,
                step=step.to_dict(),
            ),
        )
        if policy.backoff_seconds and control.wait(policy.backoff_seconds):
            result = _skipped(step, control.cancellation_reason or "execution cancelled during retry backoff")
            emitter.emit(
                "step.skipped",
                step_id=step.identity,
                data=result_event_data(result, attempt=attempt, step=step.to_dict()),
            )
            return result
    raise RuntimeError("retry loop exhausted unexpectedly")


def _dependency_skip(step: PlanStep, outcomes: dict[str, StepResult], artifacts: ArtifactStore) -> StepResult | None:
    unavailable = sorted(
        str(dependency.step_id)
        for dependency in step.depends_on
        if not dependency.optional
        and str(dependency.step_id) in outcomes
        and outcomes[str(dependency.step_id)].outcome in {FAILED, SKIPPED}
    )
    if unavailable:
        return _skipped(step, f"required dependencies unavailable: {', '.join(unavailable)}")
    missing = sorted(
        {
            kind
            for dependency in step.depends_on
            if not dependency.optional
            for kind in dependency.required_artifacts
            if not artifacts.has(kind)
        }
    )
    if missing:
        return _skipped(step, f"missing required artifacts: {', '.join(missing)}")
    return None


def _skipped(step: PlanStep, reason: str) -> StepResult:
    return StepResult(step.tool, step.action, False, {"skipped": True, "skip_reason": reason}, reason)


def _emit_progress(
    callback: Callable[[ExecutionProgress], None] | None,
    state: str,
    completed: int,
    total: int,
    step: PlanStep,
    result: StepResult | None = None,
) -> None:
    if callback is None:
        return
    try:
        callback(ExecutionProgress(state, completed, total, step, result))
    except Exception:
        return


def _plan_step_groups(indexed_steps: tuple[tuple[int, PlanStep], ...]) -> list[tuple[tuple[int, PlanStep], ...]]:
    steps = tuple(step for _, step in indexed_steps)
    if any(step.depends_on for step in steps):
        return [tuple(indexed_steps[index] for index in wave) for wave in dependency_waves(steps)]
    groups: dict[int, list[tuple[int, PlanStep]]] = {}
    for indexed_step in indexed_steps:
        groups.setdefault(_effective_execution_group(indexed_step[1]), []).append(indexed_step)
    return [tuple(groups[group_id]) for group_id in sorted(groups)]


def _effective_execution_group(step: PlanStep) -> int:
    """Infer a safe execution group for legacy manually constructed plans."""
    if step.execution_group:
        return step.execution_group
    target_type = str(step.params.get("target_type", "")).strip().lower()
    if step.tool == "ipintel":
        return 0 if target_type == "ip" else 1
    if step.tool in {"fingerprint", "whatweb", "katana"}:
        return 1
    if step.tool == "rdap":
        return 2
    if step.tool == "nmap":
        return 1 if target_type == "ip" else 2
    return 0
