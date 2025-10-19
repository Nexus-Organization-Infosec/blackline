# Blackline Project Checklist
---

## Developer / Technical Lead

### Core Development
- [ ] Define final project structure (`blackline/`, `cli/`, `backend/`, etc.)
- [ ] Implement command modules (`commands/*.py`)
- [ ] Implement backend logic (executor, runtime, JSON protocol)
- [ ] Build frontend compiler that outputs backend JSON instructions
- [ ] Add unit tests for key modules
- [ ] Configure and run tests using `pytest` or equivalent
- [ ] Implement logging for development and production
- [ ] Add versioning (`__version__` or `VERSION` file)

### DevOps / Internal Tooling
- [ ] Initialize private Git repository
- [x] Create `.gitignore`
- [ ] Set up virtual environment and dependency management (Poetry or venv)
- [ ] Set up internal CI or local build scripts
- [ ] Write `Makefile` or helper scripts (`scripts/run.sh`, `scripts/test.sh`)
- [ ] Create local build and deployment workflow

### Internal Documentation
- [ ] Write `README.md` (overview and setup instructions)
- [ ] Write `ARCHITECTURE.md` (describe compiler and backend design)
- [ ] Write `DEVELOPER_GUIDE.md` (setup, run, test, extend commands)
- [ ] Add docstrings and type hints
- [ ] Optionally set up internal docs site (MkDocs or Obsidian)

---

## Project Operations / Documentation Lead

### Internal Docs and Policies
- [ ] Write `README.md` (overview and setup instructions)
- [ ] Write `CONTRIBUTING.md` (internal process for commits, branching, reviews)
- [ ] Write `SECURITY.md` (guidelines for credentials, secrets, and sensitive data)
- [ ] Write `LICENSE` (private / proprietary notice)
- [ ] Write `ROADMAP.md` (planned milestones and goals)
- [ ] Write `CHANGELOG.md` (track changes across versions)
- [ ] Write `RELEASE_NOTES.md` (summaries for internal users or management)
- [ ] Optional: `TEST_PLAN.md` (outline QA steps)

### Coordination and Management
- [ ] Ensure documentation consistency across files
- [ ] Maintain naming conventions and document templates
- [ ] Record meeting notes and decisions
- [ ] Track dependencies, versions, and licenses
- [ ] Maintain onboarding documentation for new contributors

### Communication and Organization
- [ ] Write internal project brief or summary
- [ ] Maintain internal "What's New" log for updates
- [ ] Collect and summarize feedback from testers or internal users
- [ ] Organize backups and version archives
- [ ] Manage NDA, privacy, or compliance documents if applicable

---