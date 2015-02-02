var bitmessage = require("../lib");
var structs = bitmessage.structs;
var message = structs.message;
// var WsTransport = require("../lib/net/ws").Transport;

if (!process.browser) {
  var TcpTransport = require("../lib/net/tcp").Transport;

  describe("TCP transport", function() {
    it("should allow to communicate between two nodes");
  });
}

describe("WebSocket transport", function() {
  it("should allow to communicate between two nodes");
});
