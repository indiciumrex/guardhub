#!/bin/sh
# build.sh PKGDIR OUT: one site per js-* target; each gets clean's page plus its scripts.
set -eu
x=$1; d=$2
page() { # page DIR SCRIPT-TAGS
  mkdir -p "$1"
  printf '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>Lab site</title></head>\n<body><h1>GuardHub validation lab</h1><p>A static page.</p>%s</body></html>\n' "$2" > "$1/index.html"
}
for t in jquery bootstrap moment cdn current renamed mention; do mkdir -p "$d/$t/static"; done
cp "$x/jquery-1.12.4/package/dist/jquery.min.js" "$d/jquery/static/jquery.min.js"
page "$d/jquery" '<script src="/static/jquery.min.js"></script>'
cp "$x/bootstrap-3.3.7/package/dist/js/bootstrap.min.js" "$d/bootstrap/static/bootstrap.min.js"
page "$d/bootstrap" '<script src="/static/bootstrap.min.js"></script>'
cp "$x/moment-2.18.1/package/moment.js" "$d/moment/static/moment.js"
page "$d/moment" '<script src="/static/moment.js"></script>'
# cross-origin: never fetched (no internet in the lab); the version is the CDN path's
page "$d/cdn" '<script src="https://code.jquery.com/ui/1.12.1/jquery-ui.min.js"></script>'
cp "$x/jquery-3.7.1/package/dist/jquery.min.js" "$d/current/static/jquery.min.js"
page "$d/current" '<script src="/static/jquery.min.js"></script>'
# the file name says 1.8.3; the file is jQuery 3.7.1
cp "$x/jquery-3.7.1/package/dist/jquery.min.js" "$d/renamed/static/jquery-1.8.3.min.js"
page "$d/renamed" '<script src="/static/jquery-1.8.3.min.js"></script>'
printf '/* Shop widgets. This file needs jQuery v1.12.4 or later on the page. */\nwindow.shop = { ready: true };\n' > "$d/mention/static/app.js"
page "$d/mention" '<script src="/static/app.js"></script>'
chmod -R a+rX "$d"
