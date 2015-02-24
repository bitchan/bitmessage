var expect = require("chai").expect;

var bitmessage = require("../lib");
var structs = bitmessage.structs;
var ServicesBitfield = structs.ServicesBitfield;
var message = structs.message;
var WsTransport = require("../lib/net/ws");

var TcpTransport, tcp;

if (!process.browser) {
  TcpTransport = require("../lib/net/tcp");

  describe("TCP transport", function() {
    before(function(done) {
      tcp = new TcpTransport();
      tcp.on("error", function(err) {
        console.log("TCP transport error: " + err);
      });
      tcp.on("warning", function(warn) {
        console.log("TCP transport warning: " + warn);
      });
      // Wait some time for the server.
      setTimeout(done, 300);
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

    it("should automatically establish connection", function(done) {
      tcp.once("established", function(version) {
        expect(version.protoVersion).to.equal(3);
        expect(version.services.get(ServicesBitfield.NODE_NETWORK)).to.be.true;
        expect(version.remoteHost).to.equal("127.0.0.1");
        expect(version.port).to.equal(22333);
        expect(version.userAgent).to.be.a("string");
        expect(version.streams).to.deep.equal([1]);
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
  var ws;

  before(function(done) {
    ws = new WsTransport();
    ws.on("error", function(err) {
      console.log("WebSocket transport error: " + err);
    });
    ws.on("warning", function(warn) {
      console.log("WebSocket transport warning: " + warn);
    });
    // Wait some time for the server.
    setTimeout(done, 300);
  });

  it("should return hardcoded seeds on bootstrap", function() {
    var ws2 = new WsTransport({seeds: [["ws.example.com", 8080]]});
    return ws2.bootstrap().then(function(nodes) {
      expect(nodes).to.have.length(1);
      expect(nodes[0][0]).to.be.equal("ws.example.com");
      expect(nodes[0][1]).to.be.equal(8080);
    });
  });

  it("should allow to interconnect two nodes", function(done) {
    ws.connect("ws://127.0.0.1:22334");
    ws.once("open", function() {
      done();
    });
  });

  it("should automatically establish connection", function(done) {
    ws.once("established", function(version) {
      expect(version.protoVersion).to.equal(3);
      expect(version.services.get(ServicesBitfield.NODE_GATEWAY)).to.be.true;
      expect(version.remoteHost).to.equal("127.0.0.1");
      expect(version.port).to.equal(22334);
      expect(version.userAgent).to.be.a("string");
      expect(version.streams).to.deep.equal([1]);
      done();
    });
  });

  it("should allow to communicate", function(done) {
    ws.on("message", function cb(command, payload) {
      if (command === "echo-res") {
        expect(payload.toString()).to.equal("test");
        ws.removeListener("message", cb);
        done();
      }
    });
    ws.send("echo-req", Buffer("test"));
  });

  it("should allow to close connection", function(done) {
    ws.close();
    ws.once("close", function() {
      done();
    });
  });
});
