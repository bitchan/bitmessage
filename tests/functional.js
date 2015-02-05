var bitmessage = require("../lib");
var structs = bitmessage.structs;
var message = structs.message;
var WsTransport = require("../lib/net/ws").Transport;

var TcpTransport, tcp;

if (!process.browser) {
  TcpTransport = require("../lib/net/tcp").Transport;

  describe("TCP transport", function() {
    before(function(done) {
      tcp = new TcpTransport();
      tcp.on("error", function(err) {
        console.log("TCP transport error:", err);
      });
      // Wait some time for server.
      setTimeout(done, 1000);
    });

    it("should allow to interconnect two nodes", function(done) {
      tcp.connect(22333, "127.0.0.1");
      tcp.on("open", function() {
        done();
      });
    });

    it("should allow to close connection", function(done) {
      tcp.close();
      tcp.on("close", function() {
        done();
      });
    });
  });
}

describe("WebSocket transport", function() {
  it("should allow to communicate between two nodes");
});
