# Operational log retention

The worker supervisor now maintains the toolkit's named operational logs in both daemon and service modes. This includes web access/error, automation, distributed worker, supervisor, transfer/iPerf workers, restart and service output under `instance/`, plus `upgrade.log` and `service-reload.log` under `.twn-upgrades/`. The explicit allowlist lives in `log_retention.py`.

It checks one file per existing five-second supervisor sweep. With all 16 paths, a normal cycle takes about 80 seconds plus recovery and filesystem work. There are no added heartbeats, worker restarts, logger processes or service-manager dependencies. Deploying this code requires restarting the supervisor before retention becomes active; updating files or reloading only the web workers does not activate it.

| Supervisor environment variable | Default | Allowed range |
| --- | ---: | ---: |
| `TWN_LOG_MAX_BYTES` | 5242880 (5 MiB) | 65536–67108864 |
| `TWN_LOG_BACKUPS` | 3 | 1–10 |

Set these in the supervisor's launch environment and restart it. For boot-managed installations use the service manager's environment configuration; exporting variables in a separate shell does not change an already-running service. Invalid values produce a warning and use the documented default. No GUI control is added in this change.

At the threshold, retention copies at most the newest configured number of bytes into a private archive, flushes it to disk, shifts numbered archives (`.1` newest), and truncates the active file **without replacing its inode**. Existing append-mode writers and inherited subprocess descriptors continue writing to the same file. Launcher redirects and Python daemon logs use append mode; Apple's published [launchd implementation](https://github.com/apple-oss-distributions/launchd/blob/main/src/core.c#L4919) likewise opens job stdout/stderr with `O_APPEND`. Native service acceptance remains part of deployment testing.

A pre-existing oversized log retains only its bounded tail, rather than copying gigabytes during recovery. Copies use 64 KiB chunks. Archives have mode 0600. Each log has a single reserved `.LOGNAME.rotation` staging file, reclaimed on the next visit after an interrupted rotation. A failed copy, flush or archive publication does not truncate the live log. A failure for one log is reported without disabling supervision or skipping the remaining logs in future sweeps. Symlinks, hard-linked active logs, nonregular files and logs owned by another user are refused.

This is **best-effort retention, not a hard disk quota or lossless logging**. Copy/truncate can lose concurrent output between the snapshot and truncation; records can also be split at the retained tail boundary. Concurrent external rotation is unsupported. Slow filesystems can delay a supervisor sweep. A stopped supervisor, a write burst, archive errors or a full disk can let active logs exceed the threshold. At defaults, newly produced archives total at most 240 MiB across all 16 paths, plus live logs and one staging copy. Reducing the archive count prunes excess numbered archives on each visit; reducing the byte limit applies to new archives, while older archives age out through rotation.

The audit/evidence databases, user files, custom log paths, OS journal, root-owned network-broker logs and historical upgrade diagnostic bundles have separate lifecycles. They are not pruned by this allowlist. Keep external archival or forwarding if operational output must be preserved beyond this rolling diagnostic history.
