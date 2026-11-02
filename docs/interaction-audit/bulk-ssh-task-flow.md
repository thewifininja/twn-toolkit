# Bulk SSH task flow

The workspace now follows Hosts → Commands → Review & run. Commands is a run composer: selected saved command sets and temporary typed command sets share one ordered list. The saved library remains an explicitly separate editor. Review presents that same order, connection details and explicit host-scoped exceptions, then a single Run on N hosts boundary. Optional run settings remain secondary.

Typed commands are not saved into the library. Saved references resolve current authorized library content; signed review binds rendered commands, targets, timeouts and port. Unknown-key and legacy permissions remain off by default. Changed keys remain blocking; review itself does not contact devices.

Draft boundaries: an unadded typed draft or unsaved host/library edits prevent execution. Same-matrix saves carry selected run steps and the pending typed draft. Credentials are not retained across page navigation. Invalid typed timeouts block continuation with an actionable message.

Verification is scoped to synthetic databases, mocked connections and the loopback UI fixture. Real device execution, credential correctness and remote platform behavior are not claimed by these checks. Full-suite and independent-review results are recorded with the tested candidate, rather than assumed from the source changes.
