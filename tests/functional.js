var expect = require("chai").expect;

var bitmessage = require("../lib");
var structs = bitmessage.structs;
var message = structs.message;
var WsTransport = require("../lib/net/ws");

var TcpTransport, tcp;

if (!process.browser) {
  TcpTransport = require("../lib/net/tcp");

  describe("TCP transport", function() {
    before(function(done) {
      tcp = new TcpTransport();
      tcp.on("error", function(err) {
        console.log("TCP transport error:", err);
      });
      // Wait some time for server.
      setTimeout(done, 1000);
    });

    it("should return nothing on bootstrap by default", function() {
      return tcp.bootstrap().then(function(nodes) {
        expect(nodes).to.be.empty;
      });
    });

    it("should resolve DNS seeds on bootstrap", function() {
      this.timeout(10000);
      var tcp2 = new TcpTransport({
        dnsSeeds: [["bootstrap8444.bitmessage.org", 8444]],
      });
      return tcp2.bootstrap().then(function(nodes) {
        expect(nodes).to.be.not.empty;
        expect(nodes[0][1]).to.be.equal(8444);
      });
    });

    it("should return hardcoded seeds on bootstrap", function() {
      this.timeout(10000);
      var tcp3 = new TcpTransport({
        seeds: [["1.1.1.1", 8080]],
        dnsSeeds: [["bootstrap8444.bitmessage.org", 8444]],
      });
      return tcp3.bootstrap().then(function(nodes) {
        expect(nodes).to.have.length.at.least(2);
        expect(nodes[0][1]).to.be.equal(8444);
        expect(nodes[nodes.length - 1][0]).to.equal("1.1.1.1");
        expect(nodes[nodes.length - 1][1]).to.equal(8080);
      });
    });

    it("should allow to interconnect two nodes", function(done) {
      tcp.connect(22333, "127.0.0.1");
      tcp.once("open", function() {
        done();
      });
    });

    it("should establish connection", function(done) {
      tcp.once("established", function() {
        done();
      });
    });

    it("should allow to communicate", function(done) {
      tcp.on("message", function cb(command, payload) {
        if (command === "echo-res") {
          expect(payload.toString()).to.equal("test");
          tcp.removeListener("message", cb);
          done();
        }
      });
      tcp.send("echo-req", Buffer("test"));
    });

    it("should allow to close connection", function(done) {
      tcp.close();
      tcp.once("close", function() {
        done();
      });
    });
  });
}

describe("WebSocket transport", function() {
  it("should allow to communicate between two nodes");
});
