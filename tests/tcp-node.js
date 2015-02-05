var TcpTransport = require("../lib/net/tcp").Transport;

function start() {
  var tcp = new TcpTransport();
  tcp.listen(22333, "127.0.0.1");
}

start();
