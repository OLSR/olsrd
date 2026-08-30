#!/bin/sh
#
# Tests the ImportProto/ImportPrefix route import, for IPv4 and IPv6.
#
# olsrd has no C test harness, so this drives the real daemon: it builds a
# throwaway network namespace, puts routes in it that the import must take
# and routes it must ignore, and checks what olsrd logs at debug level 1.
#
#   make && sudo test/route-import.sh
#
# It needs iproute2 and either root or unprivileged user namespaces
# (it re-execs itself under "unshare -rn"). Nothing outside the namespace
# is touched.

set -eu

OLSRD=${OLSRD:-./olsrd}
PROTO=42                        # any route protocol would do

if [ "${ROUTE_IMPORT_INNER:-}" != 1 ]; then
  [ -x "$OLSRD" ] || { echo "SKIP: no olsrd binary at $OLSRD, run make first" >&2; exit 77; }
  OLSRD=$(readlink -f "$OLSRD")
  export OLSRD ROUTE_IMPORT_INNER=1
  if [ "$(id -u)" = 0 ]; then
    exec unshare -n -- "$0" "$@"
  fi
  exec unshare -rn -- "$0" "$@"
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

ip link set lo up

failed=0

check() {
  description=$1 expected=$2 pattern=$3
  actual=$(grep -c "$pattern" "$log" || true)
  if [ "$actual" = "$expected" ]; then
    echo "ok       - IPv$fam: $description"
  else
    echo "NOT OK   - IPv$fam: $description (expected $expected, got $actual)"
    failed=1
  fi
}

# waits for a log line rather than sleeping a guessed amount
wait_for() {
  i=0
  while ! grep -q "$1" "$log" 2>/dev/null; do
    i=$((i + 1))
    [ $i -lt 100 ] || { echo "FAIL: IPv$fam: $2"; cat "$log"; exit 1; }
    sleep 0.1
  done
}

run_family() {
  fam=$1
  log=$workdir/log$fam

  case $fam in
  4)
    ifaddr=10.12.6.66/16
    prefix1=10.12.0.0/16     prefix2=193.33.150.0/23
    take1=10.12.245.93/32    take2=193.33.150.9/32
    outside=10.247.113.235/32
    net=10.12.9.0/24         defaultroute=default
    otherproto=10.12.245.80/32
    rt_take=10.12.245.94/32  rt_outside=10.99.0.1/32
    ;;
  6)
    ifaddr=fd00:12::66/64
    prefix1=fd00:12::/32     prefix2=2001:db8::/32
    take1=fd00:12::5d/128    take2=2001:db8:150::9/128
    outside=fd00:ff::eb/128
    net=fd00:12:9::/64       defaultroute=default
    otherproto=fd00:12::50/128
    rt_take=fd00:12::5e/128  rt_outside=fd00:99::1/128
    ;;
  esac

  cat > "$workdir/olsrd.conf" <<EOF
DebugLevel 1
IpVersion $fam
AllowNoInt yes
ImportProto $PROTO
ImportPrefix $prefix1
ImportPrefix $prefix2
Interface "dummy0" { Mode "mesh" }
EOF

  ip link add dummy0 type dummy
  ip link set dummy0 up
  if [ "$fam" = 6 ]; then
    ip -6 addr add "$ifaddr" dev dummy0 nodad
  else
    ip addr add "$ifaddr" dev dummy0
  fi

  # present before olsrd starts, so these exercise the startup table dump
  ip -"$fam" route add "$take1"      dev dummy0 proto $PROTO  # take it
  ip -"$fam" route add "$take2"      dev dummy0 proto $PROTO  # take it, second prefix
  ip -"$fam" route add "$outside"    dev dummy0 proto $PROTO  # outside ImportPrefix
  ip -"$fam" route add "$net"        dev dummy0 proto $PROTO  # not a host route
  ip -"$fam" route add "$defaultroute" dev dummy0 proto $PROTO  # never a default
  ip -"$fam" route add "$otherproto" dev dummy0 proto 100     # another protocol

  "$OLSRD" -f "$workdir/olsrd.conf" -nofork -d 1 > "$log" 2>&1 &
  olsrd_pid=$!
  trap 'kill $olsrd_pid 2>/dev/null || true; rm -rf "$workdir"' EXIT

  wait_for "route import: announcing $take1" "olsrd never imported the seeded route"

  # and these exercise the rtnetlink monitor
  ip -"$fam" route add "$rt_take"    dev dummy0 proto $PROTO
  ip -"$fam" route add "$rt_outside" dev dummy0 proto $PROTO  # outside ImportPrefix
  ip -"$fam" route replace "$rt_take" dev dummy0 proto $PROTO metric 5  # must not duplicate
  ip -"$fam" route del "$take1"      dev dummy0 proto $PROTO

  wait_for "route import: withdrawing $take1" "olsrd never withdrew the deleted route"

  kill $olsrd_pid 2>/dev/null || true
  wait $olsrd_pid 2>/dev/null || true
  trap 'rm -rf "$workdir"' EXIT

  check "seeded host route is announced"        1 "announcing $take1"
  check "second ImportPrefix is honoured"       1 "announcing $take2"
  check "route added at runtime is announced"   1 "announcing $rt_take"
  check "a rewrite does not announce it twice"  1 "announcing $rt_take"
  check "deleted route is withdrawn"            1 "withdrawing $take1"
  check "address outside ImportPrefix ignored"  0 "${outside%/*}"
  check "runtime address outside it ignored"    0 "${rt_outside%/*}"
  check "non-host route ignored"                0 "${net%/*}"
  check "default route ignored"                 0 "announcing $([ "$fam" = 4 ] && echo 0.0.0.0/0 || echo ::/0)"
  check "other protocol ignored"                0 "${otherproto%/*}"

  if [ $failed -ne 0 ]; then
    echo
    echo "--- olsrd log (IPv$fam) ---"
    cat "$log"
    exit 1
  fi

  ip link del dummy0
}

run_family 4
run_family 6

echo "all route import checks passed"
