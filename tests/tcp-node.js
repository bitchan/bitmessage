var TcpTransport = require("../lib/net/tcp");

function start() {
  var tcp = new TcpTransport();
  tcp.listen(22333, "127.0.0.1");
}

start();
