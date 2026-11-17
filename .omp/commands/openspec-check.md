---
name: openspec-check
description: Run strict OpenSpec validation and contract checks across openspec/specs and openspec/changes.
---

Run `python3 scripts/validate_openspec.py` and `openspec validate --all --strict`, inspect any reported structural, requirement-length (`<= 500` chars), or relative Markdown link (`../../../` or `../../../../../`) errors, and remediate all failing artifacts until `all_checks_ok` is `true`.
