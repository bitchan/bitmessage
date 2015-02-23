var TcpTransport = require("../lib/net/tcp");

function start() {
  var server = new TcpTransport({port: 22333});
  // In node 0.12/io 1.0 we can use {host: x, port: y} syntax so it'll
  // be more compatible with the ws transport options.
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
