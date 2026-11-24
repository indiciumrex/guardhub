#!/bin/sh
# Lab-only setup for Gate M (ADR-0008 §9), run inside the isolated lab network:
# (re)create DVWA's throwaway database and log in with DVWA's documented lab
# accounts (admin/password as A, gordonb/abc123 as B for IDOR), security level
# "low". Writes the session file the active manifest names. These POSTs are lab
# setup, never the scanner's (the scanner sends GET only).
#
# The whole setup + login is retried: right after start DVWA answers before its
# database accepts connections, and a login then silently fails. Success is proven
# on a module page: it must show "Security Level: low", the account line and the
# logout link (a failed login only ever shows the login form).
set -eu
OUT=${1:?usage: login-dvwa.sh OUT_JSON}
B=http://dvwa.lab.test
token() { sed -n "s/.*name='user_token' value='\([0-9a-f]*\)'.*/\1/p" | head -n1; }
# login USER PASS -> prints the PHPSESSID of a fresh, proven session (empty on failure)
login() {
  J=$(mktemp)
  t=$(curl -s -c "$J" -b "$J" "$B/login.php" | token)
  curl -s -c "$J" -b "$J" -o /dev/null -d "username=$1&password=$2&Login=Login&user_token=$t" "$B/login.php"
  s=$(awk '$6 == "PHPSESSID" {print $7}' "$J" | tail -n1)
  rm -f "$J"
  [ -n "$s" ] || return 0
  page=$(curl -s -b "PHPSESSID=$s; security=low" "$B/vulnerabilities/sqli/")
  if echo "$page" | grep -q 'logout.php' && echo "$page" | grep -q 'Security Level:</em> low' &&
    echo "$page" | grep -q "Username:</em> $1<"; then
    echo "$s"
  fi
}
i=0
until curl -sf -o /dev/null "$B/login.php"; do i=$((i+1)); [ $i -lt 90 ] || { echo "dvwa never answered" >&2; exit 1; }; sleep 2; done
try=0
while :; do
  try=$((try+1))
  J=$(mktemp)
  t=$(curl -s -c "$J" -b "$J" "$B/setup.php" | token)
  curl -s -c "$J" -b "$J" -o /dev/null --data-urlencode "create_db=Create / Reset Database" --data-urlencode "user_token=$t" "$B/setup.php"
  rm -f "$J"
  sid=$(login admin password)
  [ -z "$sid" ] || break
  [ $try -lt 30 ] || { echo "DVWA login failed after $try attempts" >&2; exit 1; }
  sleep 3
done
sidb=$(login gordonb abc123)
[ -n "$sidb" ] || { echo "DVWA login as gordonb failed" >&2; exit 1; }
# the markers are the footer's account line exactly as DVWA writes it ("<em>Username:</em> admin<br")
printf '{"a":{"name":"A","cookie":"PHPSESSID=%s; security=low","marker":"Username:</em> admin<"},"b":{"name":"B","cookie":"PHPSESSID=%s; security=low","marker":"Username:</em> gordonb<"}}\n' "$sid" "$sidb" > "$OUT"
echo "dvwa sessions ready (attempt $try)"
