# Test results: stock Remi php56 5.6.40-47 vs patched 5.6.40-47.1

These tests ran on 2026-10-22 with `tests/el8-before-after.sh`. Each build was installed in its own clean AlmaLinux 8 container:

- **before**: `php56-php-*-5.6.40-47.el8.remi` from Remi's repo
- **after**: `php56-php-*-5.6.40-47.1.el8.remi`, built from Remi's -47 SRPM plus `packaging/remi-php56-php-5.6.40-47.1.spec.diff`

Both used the same package set (cli, common, fpm, gd, mbstring, mysqlnd, opcache, pdo, process, soap, xml) and Remi's default `php.ini`. Requests went to php-fpm over FastCGI (`cgi-fcgi`), the same way nginx or httpd talk to it. `php -m` is identical on both builds.

Raw output: `results-stock.txt`, `results-patched.txt`, `phpt-stock.log`, `phpt-patched.log`.

## Security checks: these must change

| Check | What it shows | Before (-47) | After (47.1) |
|---|---|---|---|
| OOM in a request (cli) | CVE-2026-109618: OOM no longer longjmps into shutdown code | exit 255, shutdown function **runs** | exit 1, shutdown **not run** |
| OOM in a request (php-fpm) | same, under FPM | shutdown function **RAN**, worker survives | **NOT-RUN**, worker `exited with code 1`, next request served |
| 60,000 headers in one multipart part, `memory_limit=4M` (cgi) | CVE-2026-109618 request-startup vector: extra part headers are dropped | request startup **OOMs**, script never runs | script runs |
| Session upload progress, `session.upload_progress.enabled=1` (cgi + php-fpm) | CVE-2026-109619 consumer: hard-disabled even with the setting on | **PROGRESS-WRITTEN** | **NO-PROGRESS** |

## Regression checks: these must NOT change

Each of these gave byte-identical output before and after (see the results files):

- Plain request.
- 4 MB allocation under `memory_limit`: `ALLOC-OK SHUTDOWN-RAN`. Shutdown functions still run on normal requests.
- GET with nested arrays: `a[b][c]`, `a[b][d]`, `x[]`.
- POST urlencoded arrays: `p[q][r]`, `p[q][]`, `list[]`.
- Multipart:
  - text fields and nested `tags[k][]`;
  - a 70 KB binary upload with `Content-Type: image/png` and an extra `Content-Transfer-Encoding` header (name, type, size, error and content md5 all identical);
  - an array upload `docs[]` with one real file and one empty slot (`error 4`).
- Session kept across 3 requests: `N=1 N=2 N=3`.

## PHP's own test suite (phpt)

The suite covers `Zend/tests`, `tests` (including `tests/basic/rfc1867_*`) and `ext/session/tests`, 2,563 tests in total, run with the installed binaries.

| | Passed | Failed | Skipped |
|---|---|---|---|
| Before (-47) | 2513 | 1 | 49 |
| After (47.1) | 2504 | 10 | 49 |

Exactly 9 tests change outcome, and all go from PASS to FAIL by design:

- 8 × `ext/session/tests/rfc1867*.phpt`: these tests turn upload progress on and expect it to work. The fix hard-disables it.
- `tests/lang/bug45392.phpt`: this test expects output buffered *before* an OOM to be flushed. The fix `_exit`s on OOM, so nothing is flushed.

`tests/basic/bug67198.phpt` (`php://input` with `enable_post_data_reading=Off`) fails on both builds, so it is unrelated to this patch.

## Independent code review

A separate reviewer compared the 5.6 patch hunk by hunk with the official 7.4 backport (`patches/reference-php-7.4-official-backport.diff`) and the unpatched 5.6.40 source. Verdict: **correct-with-gaps**. Every hunk the port includes is right for 5.6 (ZTS macros, types, shutdown order), and every omission compared with 7.4 is justified by 5.6 code that already behaves safely. The gaps it found are listed under "Remaining risk" in the top-level README.

## What these results do not prove

No working exploit was run. The checks show that each step the advisories describe (OOM → longjmp → shutdown, the startup OOM vector, the upload-progress consumer) is gone. The second confirmed CVE-2026-109619 path (INI warnings from per-dir `php_value`/`PHP_VALUE`) is fixed by clearing pointers at request end. That fix is covered by the code review, not by a behavioural test.

## Reproduce

```sh
# <rpms>: the patched 47.1 RPMs; <src>: a php-5.6.40 source tree (optional, for phpt); <out>: results dir
for m in stock patched; do
  docker run --rm -v "$PWD":/repo:ro -v <rpms>:/rpms:ro -v <src>:/src:ro -v <out>:/out \
    almalinux:8 /repo/tests/el8-before-after.sh $m
done
diff <out>/results-stock.txt <out>/results-patched.txt
```
