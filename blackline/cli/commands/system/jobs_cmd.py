"""Job context commands."""

from __future__ import annotations

import json
import random
import string
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from blackline.cli.commands.system.help_cmd import load_help_groups
from blackline.cli.commands.utils.shell_cmds import ShellState
from blackline.cli.ui.display import error, info, result, write_line, write_segments

ID_ALPHABET = string.ascii_uppercase + string.digits
MANUAL_MODULE = "manual"


@dataclass(frozen=True, slots=True)
class Job:
    """Structured record of execution context and results."""

    id: str
    module: str
    params: dict[str, str]
    created: str
    status: str = "initialized"
    results: list[dict[str, object]] = field(default_factory=list)


def handle_new(
    expression: str,
    state: ShellState,
    *,
    jobs_root: Path | None = None,
    created_at: datetime | None = None,
    job_id: str | None = None,
    render_summary: bool = True,
    announce_entry: bool = True,
    use_color: bool | None = None,
) -> bool:
    """Create a job and enter it as the active shell context."""
    parsed = parse_job_expression(expression)
    if not parsed:
        module, params = MANUAL_MODULE, {}
    else:
        module, params = parsed

    if module != MANUAL_MODULE and module not in available_modules():
        error(f"module not found: {module}", use_color=use_color)
        return False

    if module == "recon" and not params.get("target"):
        info("missing required fields → entering interactive mode", use_color=use_color)
        return False

    jobs_root = jobs_root or default_jobs_root()
    jobs_root.mkdir(parents=True, exist_ok=True)
    identifier = job_id or generate_job_id(jobs_root)
    created = (created_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    job = Job(id=identifier, module=module, params=params, created=created)
    save_job(job, jobs_root)
    state.active_job = identifier
    if render_summary:
        render_job(job, use_color=use_color)
    if announce_entry:
        info(f"entered job #{identifier}", use_color=use_color)
    return True


def handle_show(
    state: ShellState,
    identifier: str = "",
    *,
    jobs_root: Path | None = None,
    use_color: bool | None = None,
) -> None:
    """Show the active job."""
    target_id = normalize_job_id(identifier) or state.active_job
    if not target_id:
        info("no active job", use_color=use_color)
        return

    job = load_job(target_id, jobs_root or default_jobs_root())
    if not job:
        error(f"job not found: #{target_id}", use_color=use_color)
        return
    render_job(job, use_color=use_color)


def handle_jobs(*, jobs_root: Path | None = None, use_color: bool | None = None) -> None:
    """List stored jobs."""
    jobs_root = jobs_root or default_jobs_root()
    jobs = list_jobs(jobs_root)
    if not jobs:
        info("no jobs yet", use_color=use_color)
        return

    width = max(len(job.id) for job in jobs)
    for job in jobs:
        write_segments(
            [
                (f"#{job.id}".ljust(width + 1), "cyan"),
                ("  ", "muted"),
                (job.module.ljust(8), "white"),
                ("  ", "muted"),
                (job.status, "muted"),
            ],
            use_color=use_color,
        )


def handle_enter(
    identifier: str,
    state: ShellState,
    *,
    jobs_root: Path | None = None,
    use_color: bool | None = None,
) -> bool:
    """Enter an existing job context."""
    clean_id = normalize_job_id(identifier)
    if not clean_id:
        error("usage: enter #ID", use_color=use_color)
        return False

    if not load_job(clean_id, jobs_root or default_jobs_root()):
        error(f"job not found: #{clean_id}", use_color=use_color)
        return False

    state.active_job = clean_id
    info(f"entered job #{clean_id}", use_color=use_color)
    return True


def handle_delete_job(
    expression: str,
    state: ShellState,
    *,
    jobs_root: Path | None = None,
    use_color: bool | None = None,
) -> bool:
    """Delete one or more persisted jobs."""
    jobs_root = jobs_root or default_jobs_root()
    identifiers = parse_delete_targets(expression, jobs_root)
    if not identifiers:
        error("usage: delete #ID[, #ID] or delete *", use_color=use_color)
        return False

    deleted: list[str] = []
    missing: list[str] = []
    for identifier in identifiers:
        path = jobs_root / f"{identifier}.json"
        if not path.exists():
            missing.append(identifier)
            continue

        path.unlink()
        deleted.append(identifier)

    if state.active_job in deleted:
        identifier = state.active_job
        state.active_job = ""
        info(f"left job #{identifier}", use_color=use_color)

    for identifier in deleted:
        result(f"job deleted: #{identifier}", use_color=use_color)

    for identifier in missing:
        error(f"job not found: #{identifier}", use_color=use_color)

    return bool(deleted) and not missing


def handle_leave_job(state: ShellState, *, use_color: bool | None = None) -> bool:
    """Leave the active job context when one is active."""
    if not state.active_job:
        return False
    identifier = state.active_job
    state.active_job = ""
    info(f"left job #{identifier}", use_color=use_color)
    return True


def parse_job_expression(expression: str) -> tuple[str, dict[str, str]] | None:
    """Parse module[key=value] expressions."""
    expression = expression.strip()
    if not expression:
        return None

    if "[" not in expression:
        return expression, {}

    if not expression.endswith("]"):
        return None

    module, raw_params = expression.split("[", 1)
    module = module.strip()
    raw_params = raw_params[:-1].strip()
    if not module:
        return None

    params: dict[str, str] = {}
    if raw_params:
        for pair in raw_params.split(","):
            if "=" not in pair:
                return None
            key, value = pair.split("=", 1)
            params[key.strip()] = value.strip()
    return module, params


def render_job(job: Job, *, use_color: bool | None = None) -> None:
    """Render a compact job summary."""
    write_line("[job]", use_color=use_color)
    write_line(use_color=use_color)
    _job_row("id", f"#{job.id}", value_color="cyan", use_color=use_color)
    _job_row("module", job.module, use_color=use_color)
    for key, value in job.params.items():
        _job_row(key, value, use_color=use_color)
    _job_row("created", job.created, use_color=use_color)
    write_line(use_color=use_color)
    _job_row("status", job.status, use_color=use_color)
    _job_row("results", str(len(job.results)), use_color=use_color)
    write_line(use_color=use_color)


def save_job(job: Job, jobs_root: Path) -> Path:
    """Persist a job as JSON."""
    path = jobs_root / f"{job.id}.json"
    path.write_text(json.dumps(asdict(job), indent=2) + "\n", encoding="utf-8")
    return path


def append_job_result(identifier: str, entry: dict[str, object], jobs_root: Path | None = None) -> bool:
    """Append one structured result entry to a persisted job."""
    jobs_root = jobs_root or default_jobs_root()
    job = load_job(identifier, jobs_root)
    if job is None:
        return False

    updated = Job(
        id=job.id,
        module=job.module,
        params=job.params,
        created=job.created,
        status=job.status,
        results=[*job.results, entry],
    )
    save_job(updated, jobs_root)
    return True


def load_job(identifier: str, jobs_root: Path) -> Job | None:
    """Load one persisted job."""
    path = jobs_root / f"{normalize_job_id(identifier)}.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return Job(
        id=str(data.get("id", "")),
        module=str(data.get("module", "")),
        params={str(key): str(value) for key, value in data.get("params", {}).items()},
        created=str(data.get("created", "")),
        status=str(data.get("status", "initialized")),
        results=list(data.get("results", [])),
    )


def list_jobs(jobs_root: Path | None = None) -> list[Job]:
    """Return persisted jobs sorted by id."""
    jobs_root = jobs_root or default_jobs_root()
    if not jobs_root.exists():
        return []
    return [job for path in sorted(jobs_root.glob("*.json")) if (job := load_job(path.stem, jobs_root))]


def list_job_ids(jobs_root: Path | None = None) -> list[str]:
    """Return persisted job ids."""
    return [job.id for job in list_jobs(jobs_root)]


def parse_delete_targets(expression: str, jobs_root: Path | None = None) -> list[str]:
    """Parse delete targets from comma-separated ids or '*'."""
    expression = expression.strip()
    if not expression:
        return []
    if expression == "*":
        return list_job_ids(jobs_root)

    targets: list[str] = []
    for raw in expression.split(","):
        identifier = normalize_job_id(raw)
        if identifier:
            targets.append(identifier)
    return targets


def generate_job_id(jobs_root: Path) -> str:
    """Generate a short human-readable job id."""
    while True:
        identifier = "".join(random.choice(ID_ALPHABET) for _ in range(4))
        if not (jobs_root / f"{identifier}.json").exists():
            return identifier


def available_modules() -> set[str]:
    """Return modules that can be used to create jobs."""
    modules: set[str] = set()
    for group in load_help_groups():
        if group.id == "tools":
            modules.update(item.name for item in group.items)
    return modules


def normalize_job_id(identifier: str) -> str:
    """Normalize user-entered job identifiers."""
    return identifier.strip().upper().removeprefix("#")


def default_jobs_root() -> Path:
    """Return the default job storage path."""
    return Path(__file__).resolve().parents[3] / "storage" / "jobs"


def _job_row(label: str, value: str, *, value_color: str = "white", use_color: bool | None = None) -> None:
    write_segments(
        [
            (label.ljust(7), "muted"),
            (" : ", "muted"),
            (value, value_color),
        ],
        use_color=use_color,
    )
