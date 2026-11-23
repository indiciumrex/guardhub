#!/bin/sh
# exposed_files targets' content (ef-*.lab.test), generated at lab start into the `ef` volume:
# .DS_Store files are ignored by .gitignore, and archives/dumps are binary, so nothing here is
# committed. Runs in the nginx image itself, whose stock welcome page ef-default serves as is.
# Every target gets clean's home page, then exactly one extra file (or a different home page).
set -eu
d=/srv/ef
[ -f "$d/.done" ] && exit 0
for t in dump dumpgz phpbak archive dsstore sourcemap default schema phprun mapnames; do
  mkdir -p "$d/$t"
  cp /site/index.html "$d/$t/index.html"
done

cat > "$d/dump/backup.sql" <<'SQL'
-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: shop
CREATE TABLE `customers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);
INSERT INTO `customers` VALUES (1,'alice@example.test'),(2,'bob@example.test');
SQL

cat <<'SQL' | gzip -9 > "$d/dumpgz/db.sql.gz"
-- PostgreSQL database dump

CREATE TABLE public.orders (
    id integer NOT NULL,
    total numeric
);

COPY public.orders (id, total) FROM stdin;
1	19.90
2	5.00
\.
SQL

cat > "$d/phpbak/wp-config.php.bak" <<'PHP'
<?php
/** WordPress base configuration (lab fixture) */
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp' );
define( 'DB_PASSWORD', 'lab-not-a-secret' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
PHP

mkdir -p /tmp/site
cp /site/index.html /tmp/site/
tar -C /tmp -czf "$d/archive/backup.tar.gz" site

# .DS_Store: the buddy-allocator header ("\0\0\0\1Bud1") as Finder writes it, then padding
printf '\000\000\000\001Bud1\000\000\020\000\000\000\010\000\000\000\020\000\000\000\000\000' > "$d/dsstore/.DS_Store"
head -c 4096 /dev/zero >> "$d/dsstore/.DS_Store"

for t in sourcemap mapnames; do
  cat > "$d/$t/index.html" <<'HTML'
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>GuardHub lab</title></head><body><h1>Lab</h1><script src="/static/app.js"></script></body></html>
HTML
  mkdir -p "$d/$t/static"
  printf 'function a(){return 1}a();\n//# sourceMappingURL=app.js.map\n' > "$d/$t/static/app.js"
done
cat > "$d/sourcemap/static/app.js.map" <<'MAP'
{"version":3,"file":"app.js","sources":["../src/app.ts","../src/api.ts"],"sourcesContent":["export function a(): number { return 1 }\n","export const API = \"/api\"\n"],"names":["a"],"mappings":"AAAA"}
MAP
cat > "$d/mapnames/static/app.js.map" <<'MAP'
{"version":3,"file":"app.js","sources":["../src/app.ts"],"names":["a"],"mappings":"AAAA"}
MAP

cp /usr/share/nginx/html/index.html "$d/default/index.html"

cat > "$d/schema/dump.sql" <<'SQL'
-- MySQL dump 10.13
--
CREATE TABLE `customers` (
  `id` int NOT NULL
);
SQL

cat > "$d/phprun/index.php.bak" <<'HTML'
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Shop</title></head><body><p>Rendered by PHP</p></body></html>
HTML

chmod -R a+rX "$d"
touch "$d/.done"
