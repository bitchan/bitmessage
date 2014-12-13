var expect = require("chai").expect;

var bmcrypto = require("./lib/crypto");

describe("Bitmessage crypto", function() {
  it("should calculate sha512 hash for both node and browserify", function(done) {
    bmcrypto.sha512(new Buffer("test")).then(function(res) {
      expect(res.toString("hex")).to.equal("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
      done();
    });
  });
});
