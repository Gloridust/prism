#!/usr/bin/env bash
# Reboot test for tun.kill_switch_boot on Linux.
#
# Boots a disposable machine whose PID 1 is systemd (a privileged container),
# installs the kill switch's boot hook with the production code, restarts the
# machine for real, and checks that systemd itself brought the rules back
# before the network service started — then removes the hook, restarts again, and
# checks nothing is left. Needs docker and Go.
set -euo pipefail
cd "$(dirname "$0")/.."

img=prism-killswitch-boot-test
bin=$(mktemp -d)/prism-client-test
CGO_ENABLED=0 go test -c -o "$bin" ./cmd/prism-client/

docker build -q -t "$img" - >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv nftables iproute2 >/dev/null \
 && rm -rf /var/lib/apt/lists/* && systemctl enable systemd-networkd.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKERFILE

cid=$(docker run -d --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock -v "$bin":/prism-client-test:ro "$img")
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

vm() { docker exec -e PRISM_BOOT_TEST=1 "$cid" "$@"; }
fail() { echo "FAIL: $*" >&2; vm journalctl -b --no-pager -u prism-killswitch.service 2>/dev/null | tail -20 >&2 || true; exit 1; }

booted() { # wait until systemd has finished starting up
  for _ in $(seq 60); do
    state=$(vm systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) return 0 ;; esac
    sleep 1
  done
  fail "systemd never finished booting (state: ${state:-none})"
}
loaded() { # capture first: grep -q on a pipe would SIGPIPE nft and trip pipefail
  local out; out=$(vm nft list table inet prism_killswitch 2>/dev/null || true)
  [[ $out == *"chain out"* ]]
}
# A direct connection is "rejected" when it fails at once rather than timing out.
rejected() {
  local start=$(date +%s%N)
  vm timeout 4 bash -c 'exec 3<>/dev/tcp/203.0.113.7/81' 2>/dev/null && return 1
  (( ($(date +%s%N) - start) / 1000000 < 2000 ))
}

booted
echo "boot 1: fresh machine"
loaded && fail "ruleset present before anything was installed"
rejected && fail "direct traffic rejected before anything was installed"

vm /prism-client-test -test.run 'TestKillSwitchBootInstall$' -test.v | grep -E '^(--- |PASS|FAIL)' || fail "installing the boot hook"
[ "$(vm systemctl is-enabled prism-killswitch.service)" = enabled ] || fail "unit not enabled"
loaded && fail "installing the boot hook must not load rules by itself in this test"

echo "boot 2: restart with the boot hook installed"
docker restart -t 30 "$cid" >/dev/null
booted
[ "$(vm systemctl is-active prism-killswitch.service)" = active ] || fail "unit did not run at boot"
loaded || fail "ruleset was not loaded at boot"
ks=$(vm systemctl show -p ExecMainExitTimestampMonotonic --value prism-killswitch.service)
net=$(vm systemctl show -p ExecMainStartTimestampMonotonic --value systemd-networkd.service)
[ "$ks" -gt 0 ] && [ "$net" -gt 0 ] && [ "$ks" -le "$net" ] || fail "rules were not loaded before the network service started (kill switch done at ${ks}us, networkd started at ${net}us)"
rejected || fail "direct traffic is not rejected after the reboot"
echo "  rules loaded by systemd $(( (net - ks) / 1000 ))ms before systemd-networkd started; direct traffic rejected"

vm /prism-client-test -test.run 'TestKillSwitchBootRemove$' -test.v | grep -E '^(--- |PASS|FAIL)' || fail "removing the kill switch"

echo "boot 3: restart after -killswitch-off"
docker restart -t 30 "$cid" >/dev/null
booted
loaded && fail "ruleset came back after it was removed"
vm test -e /etc/systemd/system/prism-killswitch.service && fail "unit file left behind"
rejected && fail "direct traffic still rejected after removal"
echo "PASS: kill switch survives a reboot and is fully removed by -killswitch-off"
