# Shared by the lab's nginx targets: a static page, real 404s, no version.
server_tokens off;
root /usr/share/nginx/html;
location = / { try_files /index.html =404; }
location / { return 404; }
