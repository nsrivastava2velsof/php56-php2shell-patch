#!/bin/sh
# Roll the PHP2Shell patch back: php56-php 5.6.40-47.1  ->  5.6.40-47 (stock Remi).
#
# Deterministic by design: it downgrades from -47 RPMs you have STAGED ON DISK,
# not from whatever Remi happens to serve as "latest" at rollback time (a future
# Remi -48 would otherwise change what a bare `dnf downgrade` lands on). Then it
# reloads every php56 FPM master it finds, so the running workers pick up the
# reverted binary (an RPM downgrade alone does NOT restart FPM on EL8).
#
# Stage the -47 RPMs once, on the same box, BEFORE you need them:
#   mkdir -p /root/php56-47-rollback && cd /root/php56-47-rollback
#   dnf install -y 'dnf-command(download)'
#   dnf download php56-php-cli php56-php-common php56-php-fpm php56-php-gd \
#       php56-php-mbstring php56-php-mysqlnd php56-php-opcache php56-php-pdo \
#       php56-php-process php56-php-soap php56-php-xml
#   # (while Remi's current php56 is still -47; the set must match your install)
#
# Usage:  rollback-php56-47.1-to-47.sh [rollback_rpm_dir]   (default /root/php56-47-rollback)
set -eu

DIR=${1:-/root/php56-47-rollback}
TARGET=5.6.40-47

set +f
RPMS=$(ls "$DIR"/php56-php-*-"$TARGET".el?.remi.*.rpm 2>/dev/null || true)
set -f
[ -n "$RPMS" ] || { echo "ERROR: no $TARGET RPMs in $DIR (stage them first; see header)" >&2; exit 1; }

echo ">> before: $(rpm -q php56-php-cli php56-php-fpm | tr '\n' ' ')"
echo ">> downgrading to $TARGET from $DIR"
# shellcheck disable=SC2086
dnf -y downgrade $RPMS

echo ">> reloading php56 FPM masters"
reloaded=0
for svc in $(systemctl list-units --type=service --no-legend 'php56-php-fpm*' 2>/dev/null | awk '{print $1}'); do
	echo "   $svc"
	systemctl reload "$svc" || systemctl restart "$svc"
	reloaded=$((reloaded + 1))
done
[ "$reloaded" -gt 0 ] || echo "   (no active php56 FPM master found — reload yours by hand)"

echo ">> after:  $(rpm -q php56-php-cli php56-php-fpm | tr '\n' ' ')"
echo ">> rollback done. The engine is now stock -47 (i.e. unpatched/vulnerable again);"
echo ">> tests/verify.sh is EXPECTED to fail all three checks on this build."
