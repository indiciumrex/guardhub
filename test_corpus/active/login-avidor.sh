#!/bin/sh
# Lab-only setup for Gate M (ADR-0008 §9): log in to the lab's av-idor site as its two
# documented lab accounts (avlab/avlab.py USERS) and write the session file its manifest
# names. Lab setup POSTs, never the scanner's. Each login is proven by its marker.
set -eu
OUT=${1:?usage: login-avidor.sh OUT_JSON}
B=http://av-idor.lab.test
sid() {
  c=$(curl -s -o /dev/null -D - -d "user=$1&password=$2" "$B/login" | sed -n 's/^[Ss]et-[Cc]ookie: sid=\([0-9a-f]*\).*/\1/p')
  curl -s -b "sid=$c" "$B/" | grep -q "Signed in as $3" || { echo "av-idor login as $1 failed" >&2; exit 1; }
  echo "$c"
}
i=0
until curl -sf -o /dev/null "$B/"; do i=$((i+1)); [ $i -lt 60 ] || { echo "av-idor never answered" >&2; exit 1; }; sleep 2; done
a=$(sid alice alice-lab-pass alice.gh7@av-idor.lab.test)
b=$(sid bob bob-lab-pass bob.gh7@av-idor.lab.test)
printf '{"a":{"name":"A","cookie":"sid=%s","marker":"alice.gh7@av-idor.lab.test"},"b":{"name":"B","cookie":"sid=%s","marker":"bob.gh7@av-idor.lab.test"}}\n' "$a" "$b" > "$OUT"
echo "av-idor sessions ready"
