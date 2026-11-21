#!/bin/sh
# leaky.lab.test content, generated at lab start: a site that serves its .env,
# its .git directory, AWS credentials and an indexed backup folder. All values
# are random per run (nothing secret-shaped is committed to the repository).
set -eu
d=/srv/leak
[ -f "$d/.env" ] && exit 0
rnd() { tr -dc "$1" </dev/urandom | head -c "$2"; }
mkdir -p "$d/.git" "$d/.aws" "$d/backup"
cat > "$d/.env" <<ENV
APP_ENV=production
DATABASE_URL=postgres://app:$(rnd A-Za-z0-9 24)@db.internal:5432/app
STRIPE_SECRET_KEY=sk_live_$(rnd A-Za-z0-9 32)
APP_KEY=base64:$(rnd A-Za-z0-9 43)=
ENV
printf 'ref: refs/heads/main\n' > "$d/.git/HEAD"
printf '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = git@git.lab.test:acme/shop.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n' > "$d/.git/config"
printf '[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\n' "$(rnd A-Z0-9 16)" "$(rnd A-Za-z0-9 40)" > "$d/.aws/credentials"
: > "$d/backup/db-2026-11-01.sql.gz"; : > "$d/backup/uploads.tar.gz"
printf '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Acme shop</title></head><body><h1>Acme</h1></body></html>\n' > "$d/index.html"
chmod -R a+rX "$d"
