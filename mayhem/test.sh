#!/usr/bin/env bash
#
# mayhem/test.sh: runs the normally built pmacct daemons (mayhem/build-test, made by mayhem/build.sh) on
# known inputs and checks their exact accounting output: a pcap through pmacctd, and one NetFlow v5, v9 and
# IPFIX datagram through nfacctd. A neutered or broken program produces no/other rows and fails.
# Emits a CTRF summary (results.summary) as the PATCH grader requires.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
SRC="${SRC:-/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/mayhem/build-test/src"
FIX="$SRC/mayhem/test"
for b in pmacctd nfacctd; do
  if [ ! -x "$BIN/$b" ]; then
    echo "missing $BIN/$b: mayhem/build.sh did not build it" >&2
    emit_ctrf "pmacct-oracle" 0 1 0
    exit 1
  fi
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PORT=22055
HEADER="SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES"
passed=0; failed=0

write_conf() { # write_conf <csv output file>
  cat > "$WORK/pmacct.conf" <<CONF
daemonize: false
nfacctd_ip: 127.0.0.1
nfacctd_port: $PORT
plugins: print[out]
aggregate[out]: src_host, dst_host, src_port, dst_port, proto
print_output_file[out]: $1
print_output[out]: csv
print_history[out]: 5m
print_refresh_time[out]: 60
CONF
}

check() { # check <name> <csv output file> <expected rows, newline separated>
  local got want
  got="$( (cat "$2" 2>/dev/null || true) | sort)"
  want="$( (echo "$HEADER"; printf '%s\n' "$3") | sort)"
  if [ "$got" = "$want" ]; then
    echo "PASS $1"; passed=$((passed + 1))
  else
    echo "FAIL $1"; echo "--- expected"; echo "$want"; echo "--- got"; echo "$got"; failed=$((failed + 1))
  fi
}

# pmacctd reading a capture file: one TCP flow aggregated over two packets, plus one UDP packet.
write_conf "$WORK/pcap.csv"
timeout 60 "$BIN/pmacctd" -f "$WORK/pmacct.conf" -I "$FIX/flows.pcap" > "$WORK/pmacctd.log" 2>&1
check "pmacctd pcap aggregation" "$WORK/pcap.csv" "10.1.1.1,10.2.2.2,40000,80,tcp,2,380
10.3.3.3,10.4.4.4,5353,53,udp,1,78"

# nfacctd receiving one datagram of each flow export format over UDP.
nf_case() { # nf_case <name> <datagram file> <expected rows>
  local name="${1// /_}" out pid i
  out="$WORK/$name.csv"
  write_conf "$out"
  "$BIN/nfacctd" -f "$WORK/pmacct.conf" > "$WORK/$name.log" 2>&1 &
  pid=$!
  for i in $(seq 1 100); do grep -q "waiting for NetFlow" "$WORK/$name.log" 2>/dev/null && break; sleep 0.1; done
  if grep -q "waiting for NetFlow" "$WORK/$name.log" 2>/dev/null; then
    exec 3<>"/dev/udp/127.0.0.1/$PORT"; cat "$2" >&3; exec 3>&-
    sleep 1
  fi
  kill -INT "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  check "$1" "$out" "$3"
}
nf_case "nfacctd netflow v5" "$FIX/v5.bin" "198.51.100.1,203.0.113.9,1234,80,tcp,10,1500
10.0.0.1,10.0.0.2,53,5353,udp,3,300
192.0.2.5,192.0.2.6,0,0,icmp,1,64"
nf_case "nfacctd netflow v9" "$FIX/v9.bin" "198.51.100.1,203.0.113.9,1234,80,tcp,20,3000"
nf_case "nfacctd ipfix" "$FIX/ipfix.bin" "198.51.100.1,203.0.113.9,1234,80,tcp,20,3000"

emit_ctrf "pmacct-oracle" "$passed" "$failed" 0
