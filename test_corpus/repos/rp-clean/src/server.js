const http = require('http');
const ms = require('ms');

const port = Number(process.env.PORT || 3000);
const password = process.env.ADMIN_PASSWORD;

http.createServer((req, res) => res.end('up for ' + ms(process.uptime() * 1000)))
  .listen(port);
