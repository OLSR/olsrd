#!/bin/sh
#
# Tests the ImportProto/ImportPrefix route import.
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

cat > "$workdir/olsrd.conf" <<EOF
DebugLevel 1
IpVersion 4
AllowNoInt yes
ImportProto $PROTO
ImportPrefix 10.12.0.0/16
ImportPrefix 193.33.150.0/23
Interface "dummy0" { Mode "mesh" }
EOF

ip link set lo up
ip link add dummy0 type dummy
ip addr add 10.12.6.66/16 dev dummy0
ip link set dummy0 up

# present before olsrd starts, so these exercise the startup table dump
ip route add 10.12.245.93/32  dev dummy0 proto $PROTO   # take it
ip route add 193.33.150.9/32  dev dummy0 proto $PROTO   # take it, second prefix
ip route add 10.247.113.235/32 dev dummy0 proto $PROTO  # outside ImportPrefix
ip route add 10.12.9.0/24     dev dummy0 proto $PROTO   # not a host route
ip route add default          dev dummy0 proto $PROTO   # never a default
ip route add 10.12.245.80/32  dev dummy0 proto 100      # another protocol

"$OLSRD" -f "$workdir/olsrd.conf" -nofork -d 1 > "$workdir/log" 2>&1 &
olsrd_pid=$!
trap 'kill $olsrd_pid 2>/dev/null || true; rm -rf "$workdir"' EXIT

# wait for the startup dump rather than sleeping a guessed amount
i=0
while ! grep -q "route import: announcing 10.12.245.93/32" "$workdir/log" 2>/dev/null; do
  i=$((i + 1))
  [ $i -lt 100 ] || { echo "FAIL: olsrd never imported the seeded route"; cat "$workdir/log"; exit 1; }
  sleep 0.1
done

# and these exercise the rtnetlink monitor
ip route add 10.12.245.94/32 dev dummy0 proto $PROTO
ip route add 10.99.0.1/32    dev dummy0 proto $PROTO    # outside ImportPrefix
ip route replace 10.12.245.94/32 dev dummy0 proto $PROTO metric 5   # must not duplicate
ip route del 10.12.245.93/32 dev dummy0 proto $PROTO

i=0
while ! grep -q "route import: withdrawing 10.12.245.93/32" "$workdir/log" 2>/dev/null; do
  i=$((i + 1))
  [ $i -lt 100 ] || { echo "FAIL: olsrd never withdrew the deleted route"; cat "$workdir/log"; exit 1; }
  sleep 0.1
done

kill $olsrd_pid 2>/dev/null || true
wait $olsrd_pid 2>/dev/null || true

failed=0

check() {
  description=$1 expected=$2 pattern=$3
  actual=$(grep -c "$pattern" "$workdir/log" || true)
  if [ "$actual" = "$expected" ]; then
    echo "ok       - $description"
  else
    echo "NOT OK   - $description (expected $expected, got $actual)"
    failed=1
  fi
}

check "seeded host route is announced"        1 "announcing 10.12.245.93/32"
check "second ImportPrefix is honoured"       1 "announcing 193.33.150.9/32"
check "route added at runtime is announced"   1 "announcing 10.12.245.94/32"
check "a rewrite does not announce it twice"  1 "announcing 10.12.245.94/32"
check "deleted route is withdrawn"            1 "withdrawing 10.12.245.93/32"
check "address outside ImportPrefix ignored"  0 "10.247.113.235"
check "runtime address outside it ignored"    0 "10.99.0.1"
check "non-host route ignored"                0 "10.12.9.0"
check "default route ignored"                 0 "announcing 0.0.0.0/0"
check "other protocol ignored"                0 "10.12.245.80"

if [ $failed -ne 0 ]; then
  echo
  echo "--- olsrd log ---"
  cat "$workdir/log"
  exit 1
fi

echo "all route import checks passed"
