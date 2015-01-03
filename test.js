var expect = require("chai").expect;
var allTests = typeof window === "undefined" ?
               !!process.env.ALL_TESTS :
               window.ALL_TESTS;

var bmcrypto = require("./lib/crypto");
var bitmessage = require("./lib");
var var_int = bitmessage.structs.var_int;
var var_str = bitmessage.structs.var_str;
var var_int_list = bitmessage.structs.var_int_list;
var WIF = bitmessage.WIF;
var Address = bitmessage.Address;

describe("Crypto", function() {
  it("should implement SHA-512 hash", function() {
    expect(bmcrypto.sha512(Buffer("test")).toString("hex")).to.equal("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
  });

  it("should implement SHA-256 hash", function() {
    expect(bmcrypto.sha256(Buffer("test")).toString("hex")).to.equal("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
  });

  it("should implement RIPEMD-160 hash", function() {
    expect(bmcrypto.ripemd160(Buffer("test")).toString("hex")).to.equal("5e52fee47e6b070565f74372468cdc699de89107");
  });

  it("should implement cryptographically secure PRNG", function() {
    var size = 100;
    var rnd = bmcrypto.randomBytes(size);
    expect(Buffer.isBuffer(rnd)).to.be.true;
    expect(rnd.length).to.equal(size);
    // Very simple statistical test.
    var bytes = {};
    var sum = 0;
    var value;
    for (var i = 0; i < size; i++) {
      value = rnd[i];
      sum += value;
      if (!bytes[value]) {
        bytes[value] = 0;
      }
      bytes[value]++;
      expect(bytes[value]).to.be.below(7);
    }
    // Ideal sum = (255 / 2) * size = 12750
    expect(sum).to.be.above(10000);
    expect(sum).to.be.below(15000);
  });
});

describe("Common structures", function() {
  describe("var_int", function() {
    it("should decode", function() {
      var res;
      expect(var_int.decode.bind(null, Buffer([]))).to.throw(Error);
      expect(var_int.decode.bind(null, Buffer("fd00", "hex"))).to.throw(Error);
      expect(var_int.decode.bind(null, Buffer("ff004170706e9b0368", "hex"))).to.throw(Error);

      res = var_int.decode(Buffer([123]));
      expect(res.value).to.equal(123);
      expect(res.length).to.equal(1);
      expect(res.rest.toString("hex")).to.equal("")

      res = var_int.decode(Buffer("fd123456", "hex"));
      expect(res.value).to.equal(0x1234);
      expect(res.length).to.equal(3);
      expect(res.rest.toString("hex")).to.equal("56");

      res = var_int.decode(Buffer("fe1234567890", "hex"));
      expect(res.value).to.equal(0x12345678);
      expect(res.length).to.equal(5);
      expect(res.rest.toString("hex")).to.equal("90");

      res = var_int.decode(Buffer("ff0000001234567890", "hex"));
      expect(res.value).to.equal(0x1234567890);
      expect(res.length).to.equal(9);
      expect(res.rest.length).to.equal(0);
    });

    it("should check for lowest length on decode", function() {
      expect(var_int.decode.bind(null, Buffer("fd00fc", "hex"))).to.throw(Error);
      expect(var_int.decode.bind(null, Buffer("fe0000ffff", "hex"))).to.throw(Error);
      expect(var_int.decode.bind(null, Buffer("ff00000000ffffffff", "hex"))).to.throw(Error);
    });

    it("should encode", function() {
      expect(var_int.encode(123).toString("hex")).to.equal("7b");
      expect(var_int.encode(0x1234).toString("hex")).to.equal("fd1234");
      expect(var_int.encode(0x12345678).toString("hex")).to.equal("fe12345678");
      expect(var_int.encode(0x1234567890).toString("hex")).to.equal("ff0000001234567890");
      expect(var_int.encode(Buffer("1234567890", "hex")).toString("hex")).to.equal("ff0000001234567890");
      expect(var_int.encode.bind(null, -123)).to.throw(Error);
      expect(var_int.encode.bind(null, 0x4170706e9b0368)).to.throw(Error);
      expect(var_int.encode.bind(null, Buffer("123456789012345678", "hex"))).to.throw(Error);
      expect(var_int.encode.bind(null, "test")).to.throw(Error);
    });
  });

  describe("var_str", function() {
    it("should decode", function() {
      var res;
      res = var_str.decode(Buffer("00", "hex"));
      expect(res.str).to.equal("");
      expect(res.length).to.equal(1);
      expect(res.rest.toString("hex")).to.equal("");

      res = var_str.decode(Buffer("0474657374", "hex"));
      expect(res.str).to.equal("test");
      expect(res.length).to.equal(5);
      expect(res.rest.toString("hex")).to.equal("");

      res = var_str.decode(Buffer("0474657374ffffff", "hex"));
      expect(res.str).to.equal("test");
      expect(res.length).to.equal(5);
      expect(res.rest.toString("hex")).to.equal("ffffff");
    });

    it("should encode", function() {
      expect(var_str.encode("test").toString("hex")).to.equal("0474657374");
      expect(var_str.encode("").toString("hex")).to.equal("00");
    });
  });

  describe("var_int_list", function() {
    it("should decode", function() {
      var res;
      res = var_int_list.decode(Buffer("00", "hex"));
      expect(res.list).to.deep.equal([]);
      expect(res.length).to.equal(1);
      expect(res.rest.toString("hex")).to.equal("");

      res = var_int_list.decode(Buffer("0501fd0400ff0004000000000000fd9c40fe000186a0", "hex"));
      expect(res.length).to.equal(22);
      expect(res.list.length).to.equal(5);
      expect(res.list[0]).to.equal(1);
      expect(res.list[1]).to.equal(1024);
      expect(res.list[2] == 1125899906842624).to.be.true;
      expect(res.list[3]).to.equal(40000);
      expect(res.list[4]).to.equal(100000);
      expect(res.rest.toString("hex")).to.equal("");

      res = var_int_list.decode(Buffer("0501fd0400ff0004000000000000fd9c40fe000186a0ffffff", "hex"));
      expect(res.length).to.equal(22);
      expect(res.list.length).to.equal(5);
      expect(res.rest.toString("hex")).to.equal("ffffff");
    });

    it("should encode", function() {
      expect(var_int_list.encode([]).toString("hex")).to.equal("00");
      expect(var_int_list.encode([1, 1024, 1125899906842624, 40000, 100000]).toString("hex")).to.equal("0501fd0400ff0004000000000000fd9c40fe000186a0");
    });
  });
});

describe("WIF", function() {
  var wifSign = "5JgQ79vTBusc61xYPtUEHYQ38AXKdDZgQ5rFp7Cbb4ZjXUKFZEV";
  var wifEnc = "5K2aL8cnsEWHwHfHnUrPo8QdYyRfoYUBmhAnWY5GTpDLbeyusnE";
  var signPrivateKey = Buffer("71c95d26c716a5e85e9af9efe26fb5f744dc98005a13d05d23ee92c77e038d9f", "hex");
  var encPrivateKey = Buffer("9f9969c93c2d186787a7653f70e49be34c03c4a853e6ad0c867db0946bc433c6", "hex");

  it("should decode", function() {
    var key1 = WIF.decode(wifSign);
    expect(Buffer.isBuffer(key1)).to.be.true;
    expect(key1.length).to.equal(32);
    expect(key1.toString("hex")).to.equal(signPrivateKey.toString("hex"));
    var key2 = WIF.decode(wifEnc);
    expect(Buffer.isBuffer(key2)).to.be.true;
    expect(key2.length).to.equal(32);
    expect(key2.toString("hex")).to.equal(encPrivateKey.toString("hex"));
    var addrStr = Address({signPrivateKey: key1, encPrivateKey: key2}).encode();
    expect(addrStr).to.equal("BM-2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
  });

  it("should encode", function() {
    var wif1 = WIF.encode(signPrivateKey);
    expect(wif1).to.equal(wifSign);
    var wif2 = WIF.encode(encPrivateKey);
    expect(wif2).to.equal(wifEnc);
  });
});

describe("Address", function() {
  it("should decode Bitmessage address", function() {
    var addr = Address.decode("BM-2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z")
    expect(addr.version).to.equal(4);
    expect(addr.stream).to.equal(1);
    expect(addr.ripe.toString("hex")).to.equal("003ab6655de4bd8c603eba9b00dd5970725fdd56");
  });

  it("should decode Bitmessage address badly formatted", function() {
    var addr = Address.decode("  2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z ")
    expect(addr.version).to.equal(4);
    expect(addr.stream).to.equal(1);
    expect(addr.ripe.toString("hex")).to.equal("003ab6655de4bd8c603eba9b00dd5970725fdd56");
  });

  it("should allow to generate new Bitmessage address", function() {
    this.timeout(10000);
    var addr = Address.fromRandom();
    expect(addr.version).to.equal(4);
    expect(addr.stream).to.equal(1);
    expect(addr.signPrivateKey.length).to.equal(32);
    expect(addr.encPrivateKey.length).to.equal(32);
    var str = addr.encode();
    expect(str.slice(0, 3)).to.equal("BM-");
    var addr2 = Address.decode(str);
    expect(addr2.version).to.equal(4);
    expect(addr2.stream).to.equal(1);
    expect(addr2.ripe.length).to.equal(20);
    expect(addr2.ripe[0]).to.equal(0);
  });

  if (allTests) {
    it("should allow to generate shorter address", function() {
      this.timeout(60000);
      var addr = Address.fromRandom({ripelen: 18});
      var ripe = addr.getRipe({short: true});
      expect(ripe.length).to.be.at.most(18);
    });
  }
});
