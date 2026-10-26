# Build environment notes

- The first `python3` was the host system Python 3.9.6, so its successfully installed `.venv` is retained but unused.
- A supported Python 3.14 attempt failed in coincurve build metadata generation (see `build-logs/dependencies-install-py314.txt`); `.venv314` is retained unused.
- Python 3.13.14 succeeded using binary wheels; `.venv313` is the actual runtime.
- Boundary exception: before `TMPDIR` was explicitly set, the first two pip attempts used the host default temporary directory (`/Users/moltmike/.openclaw/tmp/pip-*`) for package installation/build artifacts, outside the task directory. This was incidental package tooling, not project source access. No such directories were opened by the agent. Subsequent installs explicitly set root-local `.tmp` and `.pip-cache`. All agent-authored files are inside the assigned working directory. This exception is disclosed rather than claiming perfect write confinement.
- No stage-two content was opened during stage one, and no external project sources or implementations were fetched.
