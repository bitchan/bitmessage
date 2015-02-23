var WsTransport = require("../lib/net/ws");

function start() {
  var server = new WsTransport({port: 22334});
  server.listen({host: "127.0.0.1", port: 22334});
  server.on("connection", function(client) {
    client.on("message", function(command, payload) {
      if (command === "echo-req") {
        client.send("echo-res", payload);
      }
    });
  });
}

start();
