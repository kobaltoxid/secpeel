# Agent instructions

## Principles

- Keep the pipeline deterministic. Unpacking, identification, advisory lookup and version matching must not depend on a language model. A model may only verify, explain and advise on results the pipeline produced.
- Never fail silently. Every file that could not be unpacked, parsed or identified must appear in the output with a reason.
- Prefer exact evidence over guesses. Record each identification with its evidence, confidence and, when the version is uncertain, a version range. Do not attach every CVE of a component when its version is unknown; report the unknown version instead.
- Do not run, exploit or modify the artifacts under analysis. Unpack them into a scratch directory.
- Stay usable from Codex, Claude Code and local models. Use plain Python 3 standard library for the core; call optional external tools (for example unblob, 7z, Ghidra) as subprocesses and degrade gracefully when they are missing.
- Do not vendor GPL-licensed tools; call them as external programs if needed.

## Related project

secdepth (`../secdepth`) consumes this project's component inventory and performs advisory matching, reachability checks and reporting. Keep the hand-off format documented and versioned.

## Git

Do not commit, push or open pull requests unless the user asks. Never add AI attribution to commits.
