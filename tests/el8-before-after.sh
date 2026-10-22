#!/bin/bash
# Before/after test of Remi php56 on EL8: stock 5.6.40-47 vs the patched 47.1 RPMs.
# Runs inside a throwaway AlmaLinux 8 container, e.g.:
#   docker run --rm -v $PWD:/repo:ro -v <rpm dir>:/rpms:ro -v <php-5.6.40 tree>:/src:ro -v <out dir>:/out \
#     almalinux:8 /repo/tests/el8-before-after.sh stock|patched
# Writes /out/results-<mode>.txt (one "name: result" line per check) and, if /src is mounted,
# /out/phpt-<mode>.txt (the failing phpt tests). Diff the two modes' files.
set -u
MODE=$1
OUT=/out/results-$MODE.txt; : > "$OUT"
r() { echo "$1: $2" | tee -a "$OUT"; }

dnf -y -q install epel-release >/dev/null 2>&1
dnf -y -q install https://rpms.remirepo.net/enterprise/remi-release-8.rpm >/dev/null 2>&1
dnf -y -q install fcgi procps-ng >/dev/null 2>&1
# the php56 sub-packages from this SRPM that a typical FPM site runs
PKGS="php56-php-cli php56-php-fpm php56-php-common php56-php-gd php56-php-mbstring php56-php-mysqlnd php56-php-opcache php56-php-pdo php56-php-xml php56-php-soap php56-php-process"
if [ "$MODE" = patched ]; then set -- $(for p in $PKGS; do ls /rpms/$p-5.6.40-47.1.*.x86_64.rpm; done)
else set -- $(for p in $PKGS; do echo $p-5.6.40-47.el8.remi; done); fi
dnf -y -q --enablerepo=remi install "$@" >/dev/null 2>&1 || { r install FAILED; exit 2; }
r package "$(rpm -q php56-php-fpm)"
B=/opt/remi/php56/root/usr
$B/bin/php -m > /out/modules-$MODE.txt

# --- security checks on cli/cgi (same engine as fpm)
sh /repo/tests/verify.sh $B/bin/php $B/bin/php-cgi | while read -r res name; do r "cgi: $name" "$res"; done

# --- php-fpm over FastCGI, the way nginx/httpd talk to it
CONF=/etc/opt/remi/php56/php-fpm.d/www.conf
sed -i 's|^listen = .*|listen = 127.0.0.1:9000|; s|^pm = .*|pm = static|; s|^pm.max_children = .*|pm.max_children = 2|; s|^;catch_workers_output.*|catch_workers_output = yes|' $CONF
sed -i 's|^;*session.upload_progress.cleanup.*|session.upload_progress.cleanup = Off|' /etc/opt/remi/php56/php.ini
LOG=/var/opt/remi/php56/log/php-fpm/error.log
$B/sbin/php-fpm -D || { r fpm-start FAILED; exit 3; }
sleep 1
mkdir -p /srv
cat > /srv/oom.php <<'EOF'
<?php register_shutdown_function(function(){ echo "SHUTDOWN-RAN\n"; });
ini_set('memory_limit','8M'); $a=array(); while(1) $a[]=str_repeat('x',100000);
EOF
cat > /srv/mem.php <<'EOF'
<?php register_shutdown_function(function(){ echo "SHUTDOWN-RAN"; });
ini_set('memory_limit','16M'); $s=str_repeat('x',4*1024*1024); echo "ALLOC-OK ";
EOF
echo '<?php echo "OK";' > /srv/ok.php
echo '<?php session_start(); echo count($_SESSION) ? "PROGRESS-WRITTEN" : "NO-PROGRESS";' > /srv/progress.php
echo '<?php session_start(); $_SESSION["n"] = isset($_SESSION["n"]) ? $_SESSION["n"] + 1 : 1; echo "N=", $_SESSION["n"];' > /srv/sess.php
cat > /srv/dump.php <<'EOF'
<?php function h($t) { return is_array($t) ? array_map('h', $t) : ($t === '' ? '' : md5_file($t)); }
foreach ($_FILES as $k => $f) $_FILES[$k]['tmp_name'] = h($f['tmp_name']);  // random path -> content md5
echo str_replace("\n", '', var_export(array($_GET, $_POST, $_FILES), true));
EOF
# fcgi <script> [VAR=value...] < body : print the response body only
fcgi() { s=$1; shift; env -i SCRIPT_FILENAME=/srv/$s REQUEST_METHOD=GET "$@" /usr/bin/cgi-fcgi -bind -connect 127.0.0.1:9000 2>&1 | tr -d '\r' | sed '1,/^$/d'; }
post() { s=$1; b=$2; shift 2; fcgi "$s" REQUEST_METHOD=POST CONTENT_LENGTH=$(wc -c < "$b") "$@" < "$b"; }
MP='CONTENT_TYPE=multipart/form-data; boundary=XB'

# security: OOM inside a request
before=$(grep -c 'exited with code 1' $LOG)
out=$(fcgi oom.php); sleep 1
r "fpm: oom shutdown function" "$(echo "$out" | grep -q SHUTDOWN-RAN && echo RAN || echo NOT-RUN)"
r "fpm: oom worker exit(1)" "$([ "$(grep -c 'exited with code 1' $LOG)" -gt "$before" ] && echo YES || echo NO)"
r "fpm: request after oom" "$(fcgi ok.php)"
# security: session upload progress
printf -- '--XB\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nk\r\n--XB\r\nContent-Disposition: form-data; name="f"; filename="f.txt"\r\nContent-Type: text/plain\r\n\r\nabc\r\n--XB--\r\n' > /tmp/progress.body
r "fpm: upload progress" "$(post progress.php /tmp/progress.body "$MP" HTTP_COOKIE=PHPSESSID=progress1)"

# regression: normal behaviour must be identical before and after
r "fpm: plain request" "$(fcgi ok.php)"
r "fpm: 4MB alloc under limit" "$(fcgi mem.php)"
r "fpm: GET nested arrays" "$(fcgi dump.php 'QUERY_STRING=a[b][c]=1&a[b][d]=2&x[]=3&x[]=4&s=t')"
printf 'p[q][r]=1&p[q][]=2&p[z]=3&list[]=a&list[]=b&plain=v' > /tmp/url.body
r "fpm: POST urlencoded arrays" "$(post dump.php /tmp/url.body CONTENT_TYPE=application/x-www-form-urlencoded)"
{ printf -- '--XB\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n'
  printf -- '--XB\r\nContent-Disposition: form-data; name="tags[k][]"\r\n\r\nt1\r\n'
  printf -- '--XB\r\nContent-Disposition: form-data; name="tags[k][]"\r\n\r\nt2\r\n'
  printf -- '--XB\r\nContent-Disposition: form-data; name="photo"; filename="a.png"\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: binary\r\n\r\n'
  head -c 70000 /dev/urandom > /tmp/a.png; cat /tmp/a.png; printf '\r\n'
  printf -- '--XB\r\nContent-Disposition: form-data; name="docs[]"; filename="b.txt"\r\nContent-Type: text/plain\r\n\r\nsecond file\r\n'
  printf -- '--XB\r\nContent-Disposition: form-data; name="docs[]"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n--XB--\r\n'; } > /tmp/upload.body
r "fpm: multipart fields + uploads" "$(post dump.php /tmp/upload.body "$MP" | sed "s/$(md5sum < /tmp/a.png | cut -c1-32)/<a.png-md5-matches>/")"
c=PHPSESSID=regress1
r "fpm: session persists" "$(fcgi sess.php HTTP_COOKIE=$c) $(fcgi sess.php HTTP_COOKIE=$c) $(fcgi sess.php HTTP_COOKIE=$c)"

# --- phpt suite (optional): Zend engine, language, basic/rfc1867, session
if [ -f /src/run-tests.php ]; then
  mkdir -p /t && cd /src && cp -r --parents run-tests.php Zend/tests tests ext/session/tests /t/ && cd /t
  TEST_PHP_EXECUTABLE=$B/bin/php TEST_PHP_CGI_EXECUTABLE=$B/bin/php-cgi NO_INTERACTION=1 \
    $B/bin/php run-tests.php -q --set-timeout 30 Zend/tests tests ext/session/tests > /tmp/phpt.log 2>&1
  grep -E '^Tests (passed|failed|skipped)' /tmp/phpt.log | tee -a "$OUT"
  cp /tmp/phpt.log /out/phpt-$MODE.log
  # -q prints failures only in the summary block, as "<title> [<file>]"
  sed -n '/^FAILED TEST SUMMARY/,/^=====/p' /tmp/phpt.log | grep -o '\[[^]]*\.phpt\]' | tr -d '[]' | sort > /out/phpt-$MODE.txt
fi
