# PHP2Shell fix for PHP 5.6 (CVE-2026-109618 / CVE-2026-109619)

Verified on 2026-10-22. In short, upstream fixed only 8.2 to 8.5, and the PHP security team published "minimal" source backports for 7.4, 8.0 and 8.1. A 5.6 port of the 7.4 backport already exists: Debian/Sury patch `0261-Avoid-state-corruption-via-bailout`, written by Arnaud Le Blanc, a PHP core developer. We use that port and do not write a new one.

- `patches/php-5.6.40-php2shell-CVE-2026-109618-109619.patch`: the 5.6 port, verbatim from `php5.6_5.6.40-104` on packages.sury.org.
- `patches/reference-php-7.4-official-backport.diff`: the official 7.4 backport (php-src branch `PHP-7.4-CVE-2026-109618-109619`, commit `712e60f9edfd`), included for review.
- `tests/verify.sh <php> <php-cgi>`: three behavioural checks. An unpatched build fails all three and a patched build passes all three.

## The two bugs

| CVE | Advisory | Mechanism |
|---|---|---|
| CVE-2026-109618 "RCE via OOM corruption" | GHSA-w8hw-w9fx-j79w | On OOM, PHP `longjmp()`s out of the current function (`zend_bailout`). In some places request memory is reachable but only half-initialised at that moment. Request shutdown then reads or frees it. Attackers reach OOM on purpose during **request startup**, before any app code runs: a multipart part with unlimited headers, a body without a usable Content-Length, and empty file controls with nested names. |
| CVE-2026-109619 "RCE via stale global state" | GHSA-6wmf-4rv5-p3rp | Worker-global pointers (SAPI, PG, EG, session state) still point into a freed request heap. The **next** request on the same worker uses them before `php_request_startup()` resets them. The confirmed consumers are **session upload progress** (RCE confirmed on mod_php *and* FPM) and INI warnings raised from per-dir `php_value` or FastCGI `PHP_VALUE`. |

## What the fix does (8.x full vs 7.4 minimal vs 5.6)

The 8.2.35 fix (`01a40e89fbfc`, about 300 files) removes `longjmp` on OOM. A *soft* OOM is raised at the next VM safe point, and a *hard* OOM at a higher threshold calls `_exit()`. Hundreds of callers were made OOM-safe to support this.

The minimal 7.4 backport, and the 5.6 port based on it, take the blunt route:

| Change | 7.4 | 5.6 port | Effect |
|---|---|---|---|
| `zend_mm_safe_error` → new `zend_mm_safe_error_ex()`: print `Fatal error` to stderr, then `_exit(1)` | ✓ | ✓ | OOM never longjmps, so half-built state is never consumed. **The worker process dies.** |
| Integer-overflow and `Balloc` errors in the allocator → `_exit` | ✓ | ✓ (plus the 5.6-only `_safe_emalloc_string`, `concat_function`, `add_*_to_string`) | Same as above. |
| `zend_mm_panic`, `zend_out_of_memory`: `exit` → `_exit` | ✓ | ✓ | No atexit handlers on a corrupt heap. |
| rfc1867: keep only `Content-Disposition`/`Content-Type` part headers, first one wins | ✓ | ✓ | Closes the many-headers OOM vector. |
| `substring_conf` int → size_t | ✓ | ✓ | Overflow hygiene. |
| GPC arrays start at the minimum table size (`array_init_singleton`) | 1 bucket | 2 buckets (5.6 uses `nTableMask==0` to mean uninitialised) | Smaller memory blow-up from nested names. |
| Session upload progress callback: `if (!enabled \|\| true) return` | ✓ | ✓ (`\|\| 1`) | **The feature is hard-disabled whatever the ini setting.** This removes the confirmed consumer. |
| Null the freed pointers: `SG(request_info).auth_*`, `content_type_dup`, `current_user` | ✓ | ✓ (and `SG(callback_func)`) | Fixes stale SAPI state. |
| `PG(http_globals)[i]` and `PG(modules_activated)` reset in `php_request_shutdown` | ✓ | ✓ | Fixes stale PG state. |
| `EG(error_handling)`, `EG(exception)` reset in `shutdown_executor` | ✓ | ✓ | Fixes stale EG state. |
| `EG(user_error_handler)` and similar reset | ✓ | n/a: 5.6 already NULLs these before destroying them (checked in the 5.6.40 source) | |
| `EG(objects_store)` reset | ✓ | n/a: 5.6's `zend_objects_store_destroy()` already NULLs `object_buckets` | |
| `zend_llist_destroy` NULLs head and tail | ✓ | ✓ | |
| VM concat overflow checks, `HT_HASH_RESET` <64 | ✓ | n/a: no such code in 5.6 | |
| New ini `max_multipart_body_parts` | ✓ | **✗, missing.** The patch header says "code is already there", but that's wrong: neither vanilla 5.6.40 nor Sury's or Remi's trees contain it | DoS hardening only. With OOM now ending in `_exit`, an unbounded part count kills a worker. It is not an RCE vector. |

## Remaining risk with the 5.6 port (known, accepted)

- `zend_error(E_ERROR, "String size overflow")` and similar calls outside the allocator still bail out (in `zend_API.c`, `ext/standard/string.c`, `math.c`, `url.c` and `php_smart_str.h`). The minimal 7.4 fix also leaves these. They need a string larger than 2 GB, so with a finite `memory_limit` the allocator OOMs (and `_exit`s) first.
- The "other error/exception/object/extension state" family in GHSA-6wmf is fixed only by the full 8.x patch. It needs an app-specific producer and consumer.
- 5.6 is still EOL with many other unfixed CVEs. This patch is a stopgap, not a reason to stay on 5.6.

## Behaviour changes to expect after deploying

1. A request that hits `memory_limit` kills its FPM worker. Shutdown functions don't run, output buffers aren't flushed, and the client gets a 502 from nginx or Apache. The `Fatal error` line goes to the worker's stderr, so it lands in the FPM log only when `catch_workers_output = yes`, not in `error_log`.
2. `session.upload_progress` stops working entirely (`$_SESSION[upload_progress_*]` is never written).

## Verification done

Builds: Sury 5.6.40 tree with patches 1–261 (`patched`), the same tree minus 0261 (`base`), and Remi `php56-php-5.6.40-47` SRPM (95 patches) plus 0261. All were configured with `--disable-all --enable-session --enable-cli --enable-cgi`.

- `tests/verify.sh`: `base` fails all 3 checks, while `patched` and `Remi+0261` pass all 3.
- phpt suite (`tests/basic ext/session/tests tests/lang Zend/tests main`, 2141 tests, run serially), patched compared with base. The new failures are 8× `ext/session/tests/rfc1867*.phpt` (upload progress disabled by design) and `tests/lang/bug45392.phpt` (OOM output no longer flushed, by design). Six other session tests also differed (2 newly failing, 4 newly passing), but all 6 passed on both builds in three reruns, so they are flaky (they depend on time and session files).
- 0261 applies to Remi's -47 tree with line offsets only, no fuzz, and builds cleanly.

## Applying it

- **Debian/Ubuntu on Sury packages:** run `apt install --only-upgrade 'php5.6*'` to get `5.6.40-104` or later, then restart php5.6-fpm and Apache.
- **RHEL/CentOS on Remi `php56` (SCL):** as of 2026-10-22, Remi's latest is still `5.6.40-47` (unfixed). Rebuild the SRPM with this patch:
  ```
  # php.spec
  Patch400: php-5.6.40-php2shell-CVE-2026-109618-109619.patch
  %patch400 -p1 -b .php2shell
  Release: 47.1%{?dist}...   # bump
  ```
  Build with mock or in an EL container matching the target, install, restart every FPM pool, then run `tests/verify.sh` against the installed `php` and `php-cgi`. The alternatives are a vendor build (TuxCare ELS; GetPageSpeed for EL7), or waiting for Remi.
- **Until patched (config mitigation, partial):** set `php_admin_flag[session.upload_progress.enabled] = off` in every FPM pool, or set it in php.ini. Don't rely on `ini_set` or `.user.ini`. Remove any `PHP_VALUE`/`PHP_ADMIN_VALUE` from nginx and Apache that triggers a warning, then restart all workers.

## Sources

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- 8.2.35 fix: https://github.com/php/php-src/commit/01a40e89fbfc
- 7.4 backport: https://github.com/php/php-src/commit/712e60f9edfd
- Sury 5.6 source: https://packages.sury.org/php/pool/main/p/php5.6/ (`php5.6_5.6.40-104…debian.tar.xz`)
- Other 5.6 ports reviewed: https://github.com/Anton-Barinov/php2shell-patches. Its `php-5.6-community-backport.patch` and `-enhanced-*` patches omit the SAPI, `zend_llist` and EG resets. The enhanced variant also does *not* force-disable upload progress, despite its comment saying it does.
