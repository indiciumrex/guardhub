#!/bin/sh
# Lab-only setup for Gate M (ADR-0008 §9): register two throwaway WebGoat lab accounts and
# log both in (WebGoat's own sign-up and login forms), then write the session file its
# manifest names. Lab setup POSTs, never the scanner's. A login is proven by start.mvc
# answering 200 for the session (an anonymous request is sent to the login page).
set -eu
OUT=${1:?usage: login-webgoat.sh OUT_JSON}
B=http://webgoat.lab.test:8080/WebGoat
PASS=ghlabpw1 # throwaway lab account, not a secret (WebGoat allows 6-10 characters)
i=0
until curl -sf -o /dev/null "$B/login"; do i=$((i+1)); [ $i -lt 120 ] || { echo "webgoat never answered" >&2; exit 1; }; sleep 2; done
session() {
  J=$(mktemp)
  curl -s -c "$J" -b "$J" -o /dev/null "$B/registration"
  curl -s -c "$J" -b "$J" -o /dev/null -d "username=$1&password=$PASS&matchingPassword=$PASS&agree=agree" "$B/register.mvc"
  rm -f "$J"; J=$(mktemp)
  curl -s -c "$J" -b "$J" -o /dev/null "$B/login"
  curl -s -c "$J" -b "$J" -o /dev/null -d "username=$1&password=$PASS" "$B/login"
  s=$(awk '$6 == "JSESSIONID" {print $7}' "$J" | tail -n1)
  rm -f "$J"
  code=$(curl -s -o /dev/null -w '%{http_code}' -b "JSESSIONID=$s" "$B/start.mvc")
  [ "$code" = 200 ] || { echo "webgoat login as $1 failed (start.mvc: $code)" >&2; exit 1; }
  echo "$s"
}
a=$(session ghlabalpha)
b=$(session ghlabbravo)
printf '{"a":{"name":"A","cookie":"JSESSIONID=%s","marker":"ghlabalpha"},"b":{"name":"B","cookie":"JSESSIONID=%s","marker":"ghlabbravo"}}\n' "$a" "$b" > "$OUT"
echo "webgoat sessions ready"
