var TcpTransport = require("../lib/net/tcp");

function start() {
  var server = new TcpTransport();
  server.listen(22333, "127.0.0.1");
  server.on("connection", function(client) {
    client.on("message", function(command, payload) {
      if (command === "echo-req") {
        client.send("echo-res", payload);
      }
    });
  });
}

start();
