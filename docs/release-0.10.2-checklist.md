# v0.10.2 release checklist

- [x] Secure SSH algorithm negotiation remains the default on every client and
  managed-server path.
- [x] Multi-SSH and Multi-Transfer provide a per-run legacy compatibility
  exception for trusted devices.
- [x] SSH and SFTP/SCP automation actions persist and forward the exception.
- [x] The managed SFTP/SCP service persists and applies the exception.
- [x] Unknown-host-key acceptance remains an independent decision.
- [x] Negotiation failures point operators to the compatibility control.
- [x] Audit events record legacy compatibility use without credentials,
  commands, remote paths, or returned content.
- [x] Built-in Help, release notes, security guidance, README, and continuity
  documentation describe the same v0.10.2 behavior.

Before release, require the complete local pytest suite, pull-request CI,
merged-main CI, annotated-tag CI/version validation, and published GitHub release.
