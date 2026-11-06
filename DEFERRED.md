# Deferred

Noted, not filed: none of these meets the bug/blocker/security/design-flaw/regression bar.

- 2026-10-21: the spec repo `docs/version-matrix.md:33` still shows acdp-verifier-py at an older spec pin. It should be refreshed when that file is next edited (cross-repo, doc-only).
- 2026-10-30: 26 open acdp-deps-bot spec-bump PRs (#52..#90) are all superseded. Main pins spec 1560e0f, and every bot branch's spec commit is an ancestor of it. Their auto-merge job is skipped, and the older ones are red because each spec change needed code. Close them in a `/sweep`; the bot (acdp-ci bump-spec-ref) could also close its predecessors itself. This is housekeeping only, since none blocks main.
