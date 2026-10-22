#!/bin/sh
# Smoke-check a PHP 5.6 build for the PHP2Shell fix (CVE-2026-109618/109619).
# Usage: tests/verify.sh /path/to/php /path/to/php-cgi
# Exit 0 = patched behaviour on all three checks.
set -u
PHP=${1:?php cli binary}
CGI=${2:?php-cgi binary}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail=0

# 1. OOM must _exit(1) at once; unpatched longjmps on and still runs shutdown code (exit 255).
cat > "$T/oom.php" <<'EOF'
<?php
register_shutdown_function(function(){ echo "SHUTDOWN-RAN\n"; });
ini_set('memory_limit','8M'); $a=array(); while(1) $a[]=str_repeat('x',100000);
EOF
out=$("$PHP" -n "$T/oom.php" 2>/dev/null); rc=$?
if [ $rc -eq 1 ] && ! echo "$out" | grep -q SHUTDOWN-RAN; then echo "PASS oom exits without running shutdown"
else echo "FAIL oom: rc=$rc (unpatched = 255 + SHUTDOWN-RAN)"; fail=1; fi

# 2. One multipart part carrying 60k junk headers must not OOM request startup.
echo '<?php echo "SCRIPT-RAN\n";' > "$T/mp.php"
{ printf -- '--XB\r\nContent-Disposition: form-data; name="a"\r\n'
  i=0; while [ $i -lt 60000 ]; do printf 'X-H%d: vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\r\n' $i; i=$((i+1)); done
  printf '\r\nhello\r\n--XB--\r\n'; } > "$T/mp.body"
run_cgi() { # $1 = script, $2 = body file, rest = extra -d flags
  s=$1; b=$2; shift 2
  CONTENT_TYPE='multipart/form-data; boundary=XB' CONTENT_LENGTH=$(wc -c < "$b") \
  REQUEST_METHOD=POST SCRIPT_FILENAME="$s" REDIRECT_STATUS=1 GATEWAY_INTERFACE=CGI/1.1 \
  "$CGI" -n "$@" < "$b" 2>&1
}
if run_cgi "$T/mp.php" "$T/mp.body" -d memory_limit=4M -d post_max_size=32M | grep -q SCRIPT-RAN
then echo "PASS multipart junk headers discarded"
else echo "FAIL multipart: request startup hit OOM"; fail=1; fi

# 3. Session upload progress must be inert (the confirmed FPM RCE consumer).
mkdir "$T/sess"
cat > "$T/up.php" <<'EOF'
<?php session_start(); echo count($_SESSION) ? "PROGRESS-WRITTEN\n" : "NO-PROGRESS\n";
EOF
{ printf -- '--XB\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nk\r\n'
  printf -- '--XB\r\nContent-Disposition: form-data; name="f"; filename="f.txt"\r\nContent-Type: text/plain\r\n\r\nabc\r\n--XB--\r\n'; } > "$T/up.body"
if HTTP_COOKIE=PHPSESSID=verifysid run_cgi "$T/up.php" "$T/up.body" \
     -d session.save_path="$T/sess" -d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=0 \
   | grep -q NO-PROGRESS
then echo "PASS session upload progress disabled"
else echo "FAIL session upload progress still active"; fail=1; fi

exit $fail
