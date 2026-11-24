#!/bin/sh
# Lab-only setup for Gate M (ADR-0008 §9), run inside the isolated lab network:
# (re)create DVWA's throwaway database and log in with DVWA's documented lab
# account (admin/password), security level "low". Writes the session file the
# active manifest names. These POSTs are lab setup, never the scanner's (the
# scanner sends GET only).
set -eu
OUT=${1:?usage: login-dvwa.sh OUT_JSON}
B=http://dvwa.lab.test
J=$(mktemp)
token() { sed -n "s/.*name='user_token' value='\([0-9a-f]*\)'.*/\1/p" | head -n1; }
i=0
until curl -sf -o /dev/null "$B/login.php"; do i=$((i+1)); [ $i -lt 90 ] || { echo "dvwa never answered" >&2; exit 1; }; sleep 2; done
t=$(curl -s -c "$J" -b "$J" "$B/setup.php" | token)
curl -s -c "$J" -b "$J" -o /dev/null --data-urlencode "create_db=Create / Reset Database" --data-urlencode "user_token=$t" "$B/setup.php"
t=$(curl -s -c "$J" -b "$J" "$B/login.php" | token)
curl -s -c "$J" -b "$J" -o /dev/null -d "username=admin&password=password&Login=Login&user_token=$t" "$B/login.php"
sid=$(awk '$6 == "PHPSESSID" {print $7}' "$J" | tail -n1)
[ -n "$sid" ] || { echo "no DVWA session" >&2; exit 1; }
curl -s -b "PHPSESSID=$sid; security=low" "$B/index.php" | grep -q "Username: admin\|Username:</em> admin\|admin" || { echo "DVWA login failed" >&2; exit 1; }
printf '{"a":{"name":"A","cookie":"PHPSESSID=%s; security=low","marker":"Username: admin"}}\n' "$sid" > "$OUT"
echo "dvwa session ready"
