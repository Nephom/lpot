# Documentation

- [`operations.md`](operations.md): safety checks, build and validation,
  CLI usage, endpoint filters, and runtime files. (Linux prerequisites are
  listed in the repository `README.md` under Requirements.)
- [`architecture.md`](architecture.md): execution flow, reboot persistence,
  comparison pipeline, and data boundaries.
- [`functions.md`](functions.md): important functions grouped by lifecycle,
  security, PCI discovery, comparison, and reporting responsibilities.
- [`call-graph.md`](call-graph.md): a generated, GitHub-style code-navigation
  reference — every function in the repository, one line on what it does,
  who calls it, and what it calls, plus flow diagrams for the startup and
  per-cycle comparison pipelines. Regenerate this file (do not hand-edit the
  call lists) whenever a function is added, renamed, or removed.
- [`development.md`](development.md): local build, tests, review checks, and
  contribution workflow.
