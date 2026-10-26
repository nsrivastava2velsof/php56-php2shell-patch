# PHP2Shell patch — three-phase validation (before / after / rollback)

**Date:** 2026-10-26 · **Tester VM:** AlmaLinux 8.10 (RHEL 8.10 rebuild), kernel 4.18.0-553.el8_10
**Engine:** Remi `php56` SCL, `/opt/remi/php56`, UKSS-production `php.ini`, exercised through both `php` (CLI) and `php-cgi` (the FastCGI path nginx/httpd use).
**Raw evidence:** [`three-phase-validation.log`](three-phase-validation.log)

This run proves two things in one pass: (a) the `5.6.40-47.1` patch closes all three PHP2Shell behaviours, and (b) the rollback script restores the exact prior engine, so the change is fully reversible.

## What each check does

| # | Check | CVE | Vulnerable result | Fixed result |
|---|---|---|---|---|
| 1 | OOM inside a request, with a shutdown handler registered | CVE-2026-109618 | OOM longjmps on; shutdown handler **runs**; `exit 255` | OOM aborts the process; shutdown handler **does not run**; `exit 1` |
| 2 | One multipart part carrying 60,000 junk headers at `memory_limit=4M` | CVE-2026-109618 (request-startup vector) | request dies at startup; script **never runs** (no `SCRIPT-RAN`) | junk headers discarded; script **runs** (`SCRIPT-RAN`) |
| 3 | `session.upload_progress.enabled=1`, upload carrying `PHP_SESSION_UPLOAD_PROGRESS` | CVE-2026-109619 | progress written to session (`PROGRESS-WRITTEN`, non-empty session file) | inert (`NO-PROGRESS`, empty session file) |

## Method

The same three checks were run unchanged at each of three engine states:

1. **Phase 1 — BEFORE:** engine rolled to stock `5.6.40-47` (unpatched).
2. **Phase 2 — AFTER:** engine upgraded to `5.6.40-47.1` (patched) via the staged RPMs, FPM reloaded.
3. **Phase 3 — ROLLBACK:** engine rolled back to `5.6.40-47` with `packaging/rollback-php56-47.1-to-47.sh`, FPM reloaded.

Engine version was confirmed with `rpm -q` at every phase, and FPM was confirmed `active` throughout (changes applied by `systemctl reload`, i.e. no full restart).

## Results

| Check | Phase 1 `-47` (before) | Phase 2 `47.1` (after) | Phase 3 `-47` (rollback) |
|---|---|---|---|
| 1 — OOM / shutdown | VULNERABLE — `exit=255`, `SHUTDOWN-RAN` | **FIXED** — `exit=1`, no `SHUTDOWN-RAN` | VULNERABLE — `exit=255`, `SHUTDOWN-RAN` |
| 2 — multipart 60k headers | VULNERABLE — no `SCRIPT-RAN` | **FIXED** — `SCRIPT-RAN` | VULNERABLE — no `SCRIPT-RAN` |
| 3 — session upload-progress | VULNERABLE — `PROGRESS-WRITTEN`, 330 B | **FIXED** — `NO-PROGRESS`, 0 B | VULNERABLE — `PROGRESS-WRITTEN`, 330 B |

All three checks behaved identically in Phase 1 and Phase 3, confirming the rollback restores the exact pre-patch engine.

## Rollback characteristics (measured on this VM)

- Downgrade transaction (11 packages, from local staged RPMs): **~6 seconds**.
- FPM reload: sub-second.
- The RPM change alone does **not** restart FPM on EL8; the running binary is swapped by the `systemctl reload` the script issues.
- Rollback is deterministic: it downgrades from `-47` RPMs staged on disk, not from whatever Remi currently serves as "latest".

## Verdict

**PASS.** On `5.6.40-47.1` every one of the three PHP2Shell behaviours is closed; on stock `5.6.40-47` every one is reproducible, both before patching and after rollback. The patch is effective against the tested vectors, introduces no change to the engine beyond the documented behaviours, and is cleanly and quickly reversible.

**Scope of this evidence:** these are behavioural checks of the three mechanisms the advisories describe, not a live end-to-end exploit. The second CVE-2026-109619 consumer (INI warnings from per-dir `php_value`/`PHP_VALUE`) is addressed by the pointer-reset hunks and is covered by code review, not by a behavioural check here. See the top-level README "Remaining risk" for the known limits of a minimal backport.
