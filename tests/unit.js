var expect = require("chai").expect;
var allTests = (global.__env__ || process.env).ALL_TESTS === "1";

var bufferEqual = require("buffer-equal");
var bitmessage = require("../lib");
var bmcrypto = require("../lib/crypto");
var structs = bitmessage.structs;
var message = structs.message;
var object = structs.object;
var var_int = structs.var_int;
var var_str = structs.var_str;
var var_int_list = structs.var_int_list;
var net_addr = structs.net_addr;
var inv_vect = structs.inv_vect;
var encrypted = structs.encrypted;
var ServicesBitfield = structs.ServicesBitfield;
var PubkeyBitfield = structs.PubkeyBitfield;
var messages = bitmessage.messages;
var version = messages.version;
var addr = messages.addr;
var inv = messages.inv;
var getdata = messages.getdata;
var error = messages.error;
var objects = bitmessage.objects;
var getpubkey = objects.getpubkey;
var pubkey = objects.pubkey;
var msg = objects.msg;
var broadcast = objects.broadcast;
var WIF = bitmessage.WIF;
var POW = bitmessage.POW;
var Address = bitmessage.Address;
var UserAgent = bitmessage.UserAgent;

var skipPow = {skipPow: true};

describe("Crypto", function() {
  it("should implement SHA-1 hash", function() {
    expect(bmcrypto.sha1(Buffer("test")).toString("hex")).to.equal("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
  });

  it("should implement SHA-256 hash", function() {
    expect(bmcrypto.sha256(Buffer("test")).toString("hex")).to.equal("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
  });

  it("should implement SHA-512 hash", function() {
    expect(bmcrypto.sha512(Buffer("test")).toString("hex")).to.equal("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
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
    expect(sum).to.be.above(5000);
    expect(sum).to.be.below(20000);
  });

  it("should generate private keys", function() {
    var privateKey = bmcrypto.getPrivate();
    expect(Buffer.isBuffer(privateKey)).to.be.true;
    expect(privateKey.length).to.equal(32);
    var sum = 0;
    for (var i = 0; i < 32; i++) { sum += privateKey[i]; }
    expect(sum).to.be.above(0);
    expect(sum).to.be.below(8160);
  });

  it("should allow to convert private key to public", function() {
    var privateKey = Buffer(32);
    privateKey.fill(1);
    expect(bmcrypto.getPublic(privateKey).toString("hex")).to.equal("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1");
  });

  it("should allow to sign and verify message", function() {
    var privateKey = Buffer(32);
    privateKey.fill(1);
    var publicKey = bmcrypto.getPublic(privateKey);
    var message = Buffer("test");
    return bmcrypto.sign(privateKey, message).then(function(sig) {
      expect(Buffer.isBuffer(sig)).to.be.true;
      expect(sig.toString("hex")).to.equal("304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa");
      return bmcrypto.verify(publicKey, message, sig);
    });
  });

  it("should allow to encrypt and decrypt message", function() {
    var privateKeyA = bmcrypto.getPrivate();
    var publicKeyA = bmcrypto.getPublic(privateKeyA);
    return bmcrypto.encrypt(publicKeyA, Buffer("msg to a")).then(function(buf) {
      expect(Buffer.isBuffer(buf)).to.be.true;
      return bmcrypto.decrypt(privateKeyA, buf).then(function(plaintext) {
        expect(Buffer.isBuffer(plaintext)).to.be.true;
        expect(plaintext.toString()).to.equal("msg to a");
      });
    });
  });
});

// TODO(Kagami): Add tests for encodePayload/decodePayload as well.
describe("Common structures", function() {
  describe("message", function() {
    it("should decode", function() {
      var res;
      res = message.decode(Buffer("e9beb4d97465737400000000000000000000000770b33ce97061796c6f6164", "hex"));
      expect(res.command).to.equal("test");
      expect(res.payload.toString()).to.equal("payload");
      expect(res.length).to.equal(31);
      expect(res.rest.toString("hex")).to.equal("");

      res = message.decode(Buffer("e9beb4d90000000000000000000000000000000770b33ce97061796c6f6164", "hex"));
      expect(res.command).to.equal("");
    });

    it("should throw when decoding message with truncated payload", function() {
      expect(message.decode.bind(null, Buffer("e9beb4d97465737400000000000000000000000770b33ce97061796c6f61", "hex"))).to.throw(Error);
    });

    it("should encode", function() {
      expect(message.encode("test", Buffer("payload")).toString("hex")).to.equal("e9beb4d97465737400000000000000000000000770b33ce97061796c6f6164");
    });

    it("should encode empty payload without second argument", function() {
      var res = message.decode(message.encode("ping"));
      expect(res.command).to.equal("ping");
      expect(res.payload.toString("hex")).to.equal("");
    });

    it("should decode messages in stream mode", function() {
      var res = message.tryDecode(Buffer(""));
      expect(res).to.not.exist;

      res = message.tryDecode(Buffer(25));
      expect(res.error).to.match(/magic not found/i);
      expect(res.rest.toString("hex")).to.equal("");
      expect(res).to.not.have.property("message");

      res = message.tryDecode(message.encode("test", Buffer([1,2,3])));
      expect(res).to.not.have.property("error");
      expect(res.message.command).to.equal("test");
      expect(res.message.payload.toString("hex")).to.equal("010203");
      expect(res.rest.toString("hex")).to.equal("");

      var encoded = message.encode("cmd", Buffer("buf"));
      encoded[20] ^= 1;  // Corrupt checksum
      encoded = Buffer.concat([encoded, Buffer("rest")]);
      res = message.tryDecode(encoded);
      expect(res.error).to.match(/bad checksum/i);
      expect(res.rest.toString()).to.equal("rest");
      expect(res).to.not.have.property("message");

      encoded = Buffer.concat([Buffer(10), encoded]);
      res = message.tryDecode(encoded);
      expect(res.error).to.match(/magic in the middle/i);
      expect(res.rest).to.have.length(31);
      expect(res.rest.readUInt32BE(0)).to.equal(message.MAGIC);
      expect(res).to.not.have.property("message");
    });

    it("should check for max payload length", function() {
      var fn = message.encode.bind(null, "test", Buffer(2000000));
      expect(fn).to.throw(/payload is too big/i);

      var bigmsg = message.encode("test");
      bigmsg.writeUInt32BE(2000000, 16);
      fn = message.decode.bind(null, bigmsg);
      expect(fn).to.throw(/payload is too big/i);
    });
  });

  describe("object", function() {
    it("should encode and decode", function() {
      var nonce = Buffer(8);
      var res = object.decode(object.encode({
        nonce: nonce,
        ttl: 100,
        type: 2,
        version: 1,
        objectPayload: Buffer("test"),
      }), skipPow);

      expect(bufferEqual(nonce, res.nonce)).to.be.true;
      expect(res.ttl).to.be.at.most(100);
      expect(res.type).to.equal(2);
      expect(res.version).to.equal(1);
      expect(res.stream).to.equal(1);
      expect(res.headerLength).to.equal(22);
      expect(res.objectPayload.toString()).to.equal("test");
    });

    it("shouldn't encode too big TTL", function() {
      expect(object.encode.bind(null, {
        nonce: Buffer(8),
        ttl: 10000000,
        type: 2,
        version: 1,
        objectPayload: Buffer("test"),
      })).to.throw(Error);
    });

    it("shouldn't encode message payload bigger than 2^18 bytes", function() {
      expect(object.encodePayload.bind(null, {
        nonce: Buffer(8),
        ttl: 100,
        type: object.MSG,
        version: 1,
        objectPayload: Buffer(300000),
      })).to.throw(/too big/i);
    });

    it("shouldn't decode message payload bigger than 2^18 bytes", function() {
      var encoded = object.encodePayload({
        nonce: Buffer(8),
        ttl: 100,
        type: object.MSG,
        version: 1,
        objectPayload: Buffer("test"),
      });
      encoded = Buffer.concat([encoded, Buffer(300000)]);
      expect(object.decodePayload.bind(null, encoded)).to.throw(/too big/i);
    });

    it("shouldn't decode object with insufficient nonce", function() {
      expect(object.decode.bind(null, object.encode({
        nonce: Buffer(8),
        ttl: 100,
        type: 2,
        version: 1,
        objectPayload: Buffer("test"),
      }))).to.throw(/insufficient/i);
    });
  });

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

      // Truncated input.
      expect(var_str.decode.bind(null, Buffer("04746573", "hex"))).to.throw(Error);
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

      // Truncated input.
      expect(var_int_list.decode.bind(null, Buffer("0501fd0400ff0004000000000000fd9c40fe000186", "hex"))).to.throw(Error);
    });

    it("should encode", function() {
      expect(var_int_list.encode([]).toString("hex")).to.equal("00");
      expect(var_int_list.encode([1, 1024, 1125899906842624, 40000, 100000]).toString("hex")).to.equal("0501fd0400ff0004000000000000fd9c40fe000186a0");
    });
  });

  // FIXME(Kagami): Add more tests for inet_pton, inet_ntop; add more
  // fail tests.
  describe("net_addr", function() {
    it("should decode", function() {
      var res;
      res = net_addr.decode(Buffer("0000000054aaf6c000000001000000000000000100000000000000000000ffff7f00000120fc", "hex"));
      expect(res.time.getTime()).to.equal(1420490432000);
      expect(res.stream).to.equal(1);
      expect(res.services.get(ServicesBitfield.NODE_NETWORK)).to.be.true;
      expect(res.host).to.equal("127.0.0.1");
      expect(res.port).to.equal(8444);

      expect(net_addr.decode.bind(null, Buffer("000000000000000100000000000000000000ffff7f00000120fc", "hex"))).to.throw(Error);;

      res = net_addr.decode(Buffer("000000000000000100000000000000000000ffff7f00000120fc", "hex"), {short: true});
      expect(res.services.get(ServicesBitfield.NODE_NETWORK)).to.be.true;
      expect(res.host).to.equal("127.0.0.1");
      expect(res.port).to.equal(8444);

      res = net_addr.decode(Buffer("000000000000000100000000000000000000000000000001fde8", "hex"), {short: true});
      expect(res.services.get(ServicesBitfield.NODE_NETWORK)).to.be.true;
      expect(res.host).to.equal("0:0:0:0:0:0:0:1");
      expect(res.port).to.equal(65000);
    });

    it("should encode", function() {
      var time = new Date(1420490432000);
      expect(net_addr.encode({time: time, stream: 1, services: ServicesBitfield().set(ServicesBitfield.NODE_NETWORK), host: "127.0.0.1", port: 8444}).toString("hex")).to.equal("0000000054aaf6c000000001000000000000000100000000000000000000ffff7f00000120fc");
      expect(net_addr.encode({short: true, services: ServicesBitfield().set(ServicesBitfield.NODE_NETWORK), host: "127.0.0.1", port: 8444}).toString("hex")).to.equal("000000000000000100000000000000000000ffff7f00000120fc");
      expect(net_addr.encode({short: true, host: "::1", port: 65000}).toString("hex")).to.equal("000000000000000100000000000000000000000000000001fde8");
    });

    it("should encode IPv4-mapped IPv6", function() {
      var encoded = net_addr.encode({host: "::ffff:127.0.0.1", port: 1234});
      expect(net_addr.decode(encoded).host).to.equal("127.0.0.1");
    });

    it("shouldn't encode bad IPv4", function() {
      var opts = {host: " 127.0.0.1", port: 1234};
      expect(net_addr.encode.bind(null, opts)).to.throw(/bad octet/i);
    });
  });

  describe("inv_vect", function() {
    it("should encode", function() {
      expect(inv_vect.encode("test").toString("hex")).to.equal("faadcaf60afd35dfcdb5e9ea0d0a0531f6338c62187cff37a1efe11f1d41a348");
    });
  });

  describe("encrypted", function() {
    it("should encode and decode", function() {
      var iv = Buffer(16);
      var ephemPublicKey = Buffer(65);
      ephemPublicKey[0] = 0x04;
      var ciphertext = Buffer("test");
      var mac = Buffer(32);
      var inopts = {
        iv: iv,
        ephemPublicKey: ephemPublicKey,
        ciphertext: ciphertext,
        mac: mac,
      };

      var encoded = encrypted.encode(inopts);
      expect(encoded.length).to.equal(122);
      var outopts = encrypted.decode(encoded);
      expect(bufferEqual(iv, outopts.iv)).to.be.true;
      expect(bufferEqual(ephemPublicKey, outopts.ephemPublicKey)).to.be.true;
      expect(ciphertext.toString()).to.equal("test");
      expect(bufferEqual(mac, outopts.mac)).to.be.true;
    });
  });

  describe("service features", function() {
    it("should allow to check bits", function() {
      expect(ServicesBitfield(Buffer("0000000000000001", "hex")).get(ServicesBitfield.NODE_NETWORK)).to.be.true;
    });

    it("should allow to set bits", function() {
      expect(ServicesBitfield().set([ServicesBitfield.NODE_NETWORK]).buffer.toString("hex")).to.equal("0000000000000001");
      expect(ServicesBitfield().set(ServicesBitfield.NODE_NETWORK).buffer.toString("hex")).to.equal("0000000000000001");
    });
  });

  describe("pubkey features", function() {
    it("should allow to check bits", function() {
      expect(PubkeyBitfield(Buffer("00000003", "hex")).get([PubkeyBitfield.DOES_ACK, PubkeyBitfield.INCLUDE_DESTINATION])).to.be.true;
    });

    it("should allow to set bits", function() {
      expect(PubkeyBitfield().set([PubkeyBitfield.INCLUDE_DESTINATION, PubkeyBitfield.DOES_ACK]).buffer.toString("hex")).to.equal("00000003");
      expect(PubkeyBitfield().set(PubkeyBitfield.DOES_ACK).buffer.toString("hex")).to.equal("00000001");
    });
  });
});

// TODO(Kagami): Add tests for encodePayload/decodePayload as well.
describe("Message types", function() {
  it("should get command for encoded message", function() {
    var encoded = message.encode("test", Buffer(0));
    expect(messages.getCommand(encoded)).to.equal("test");
    expect(messages.getCommand(Buffer("test"))).to.be.undefined;
  });

  describe("version", function() {
    it("should encode and decode", function() {
      var nonce = Buffer(8);
      var encoded = version.encode({
        remoteHost: "1.2.3.4",
        remotePort: 48444,
        port: 8444,
        nonce: nonce,
      });
      expect(message.decode(encoded).command).to.equal("version");
      var res = version.decode(encoded);
      expect(res.version).to.equal(3);
      expect(res.services.get(ServicesBitfield.NODE_NETWORK)).to.be.true;
      expect(res.time).to.be.instanceof(Date);
      expect(res.remoteHost).to.equal("1.2.3.4");
      expect(res.remotePort).to.equal(48444);
      expect(res.port).to.equal(8444);
      expect(bufferEqual(res.nonce, nonce)).to.be.true;
      expect(UserAgent.parse(res.userAgent)).to.deep.equal(UserAgent.SELF);
      expect(res.streamNumbers).to.deep.equal([1]);
      expect(res.length).to.equal(101);
    });

    it("should accept raw user agent string", function() {
      var res = version.decode(version.encode({
        remoteHost: "1.2.3.4",
        remotePort: 48444,
        port: 8444,
        userAgent: "/test:0.0.1/",
        nonce: Buffer(8),
      }));
      expect(res.userAgent).to.equal("/test:0.0.1/");
    });

    it("should fail on connection to self", function() {
      expect(version.decode.bind(null, version.encode({
        remoteHost: "1.2.3.4",
        remotePort: 48444,
        port: 8444,
      }))).to.throw(/connection to self/i);
    });
  });

  describe("addr", function() {
    it("should encode and decode", function() {
      var res = addr.decode(addr.encode([]));
      expect(res.length).to.equal(1);
      expect(res.addrs).to.deep.equal([]);

      var encoded = addr.encode([
        {host: "1.2.3.4", port: 8444},
        {host: "ff::1", port: 18444},
      ]);
      expect(message.decode(encoded).command).to.equal("addr");
      res = addr.decode(encoded);
      expect(res.length).to.equal(77);
      expect(res.addrs.length).to.equal(2);
      expect(res.addrs[0].host).to.equal("1.2.3.4");
      expect(res.addrs[0].port).to.equal(8444);
      expect(res.addrs[1].host).to.equal("ff:0:0:0:0:0:0:1");
      expect(res.addrs[1].port).to.equal(18444);
    });

    it("shouldn't encode/decode more than 1000 entires", function() {
      expect(addr.encode.bind(null, Array(2000))).to.throw(/too many/i);
      expect(addr.decodePayload.bind(null, var_int.encode(2000))).to.throw(/too many/i);
    });
  });

  describe("inv", function() {
    it("should encode and decode", function() {
      var vect1 = inv_vect.encode(Buffer("test"));
      var vect2 = inv_vect.encode(Buffer("test2"));
      var inventory = [vect1, vect2];
      var encoded = inv.encode(inventory);
      expect(message.decode(encoded).command).to.equal("inv");
      var res = inv.decode(encoded);
      expect(res.inventory.length).to.equal(2);
      expect(bufferEqual(res.inventory[0], vect1)).to.be.true;
      expect(bufferEqual(res.inventory[1], vect2)).to.be.true;
      expect(res.length).to.equal(65);
    });

    it("shouldn't encode/decode more than 50000 entires", function() {
      expect(inv.encode.bind(null, Array(60000))).to.throw(/too many/i);
      expect(inv.decodePayload.bind(null, var_int.encode(60000))).to.throw(/too many/i);
    });
  });

  describe("getdata", function() {
    it("should encode and decode", function() {
      var vect1 = inv_vect.encode(Buffer("test"));
      var vect2 = inv_vect.encode(Buffer("test2"));
      var inventory = [vect1, vect2];
      var encoded = getdata.encode(inventory);
      expect(message.decode(encoded).command).to.equal("getdata");
      var res = getdata.decode(encoded);
      expect(res.inventory.length).to.equal(2);
      expect(bufferEqual(res.inventory[0], vect1)).to.be.true;
      expect(bufferEqual(res.inventory[1], vect2)).to.be.true;
      expect(res.length).to.equal(65);
    });

    it("shouldn't encode/decode more than 50000 entires", function() {
      expect(getdata.encode.bind(null, Array(60000))).to.throw(/too many/i);
      expect(getdata.decodePayload.bind(null, var_int.encode(60000))).to.throw(/too many/i);
    });
  });

  describe("error", function() {
    it("should encode and decode", function() {
      var encoded = error.encode({errorText: "test"});
      expect(message.decode(encoded).command).to.equal("error");
      var res = error.decode(encoded);
      expect(res.fatal).to.equal(0);
      expect(res.banTime).to.equal(0);
      expect(res.vector).to.not.exist;
      expect(res.errorText).to.equal("test");
      expect(res.length).to.equal(8);

      var vector = inv_vect.encode(Buffer("test"));
      var res = error.decode(error.encode({
        fatal: error.FATAL,
        banTime: 120,
        vector: vector,
        errorText: "fatal error",
      }));
      expect(res.fatal).to.equal(2);
      expect(res.banTime).to.equal(120);
      expect(bufferEqual(res.vector, vector)).to.be.true;
      expect(res.errorText).to.equal("fatal error");
      expect(res.length).to.equal(47);
    });
  });
});

// TODO(Kagami): Add tests for encodePayloadAsync/decodePayloadAsync as well.
describe("Object types", function() {
  var signPrivateKey = Buffer("71c95d26c716a5e85e9af9efe26fb5f744dc98005a13d05d23ee92c77e038d9f", "hex");
  var signPublicKey = bmcrypto.getPublic(signPrivateKey);
  var encPrivateKey = Buffer("9f9969c93c2d186787a7653f70e49be34c03c4a853e6ad0c867db0946bc433c6", "hex");
  var encPublicKey = bmcrypto.getPublic(encPrivateKey);
  var fromV2 = Address({
    version: 2,
    signPrivateKey: signPrivateKey,
    encPrivateKey: encPrivateKey,
  });
  var fromV3 = Address({
    version: 3,
    signPrivateKey: signPrivateKey,
    encPrivateKey: encPrivateKey,
  });
  var fromV4 = Address({
    signPrivateKey: signPrivateKey,
    encPrivateKey: encPrivateKey,
  });
  var from = fromV4;

  it("should get type of the encoded object message", function() {
    var encoded = object.encode({
      nonce: Buffer(8),
      ttl: 100,
      type: object.BROADCAST,
      version: 1,
      objectPayload: Buffer("test"),
    });
    expect(objects.getType(encoded)).to.equal(object.BROADCAST);
    expect(objects.getType(Buffer(4))).to.be.undefined;
  });

  it("should get type of the object message payload", function() {
    var encoded = object.encodePayload({
      nonce: Buffer(8),
      ttl: 333,
      type: object.MSG,
      version: 1,
      objectPayload: Buffer("test"),
    });
    expect(objects.getPayloadType(encoded)).to.equal(object.MSG);
    expect(objects.getPayloadType(Buffer(7))).to.be.undefined;
  });

  describe("getpubkey", function() {
    it("should encode and decode getpubkey v3", function() {
      return getpubkey.encodeAsync({
        ttl: 100,
        to: "BM-2D8Jxw5yiepaQqxrx43iPPNfRqbvWoJLoU",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return getpubkey.decodeAsync(buf, skipPow);
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(100);
        expect(res.type).to.equal(object.GETPUBKEY);
        expect(res.version).to.equal(3);
        expect(res.stream).to.equal(1);
        expect(res.ripe.toString("hex")).to.equal("003ab6655de4bd8c603eba9b00dd5970725fdd56");
        expect(res).to.not.have.property("tag");
      });
    });

    it("should encode and decode getpubkey v4", function() {
      return getpubkey.encodeAsync({
        ttl: 100,
        to: "2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return getpubkey.decodeAsync(buf, skipPow);
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(100);
        expect(res.type).to.equal(object.GETPUBKEY);
        expect(res.version).to.equal(4);
        expect(res.stream).to.equal(1);
        expect(res).to.not.have.property("ripe");
        expect(res.tag.toString("hex")).to.equal("facf1e3e6c74916203b7f714ca100d4d60604f0917696d0f09330f82f52bed1a");
      });
    });

    it("shouldn't decode getpubkey with insufficient nonce", function(done) {
      return getpubkey.encodeAsync({
        ttl: 100,
        to: "2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z",
        skipPow: true,
      }).then(getpubkey.decodeAsync).catch(function(err) {
        expect(err.message).to.match(/insufficient/i);
        done();
      });
    });

    if (allTests) {
      it("should encode and decode getpubkey with nonce", function() {
        this.timeout(300000);
        return getpubkey.encodePayloadAsync({
          ttl: 100,
          to: "2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z",
        }).then(function(payload) {
          expect(POW.check({ttl: 100, payload: payload})).to.be.true;;
          return getpubkey.decodePayloadAsync(payload);
        }).then(function(res) {
          expect(res.ttl).to.be.at.most(100);
          expect(res.tag.toString("hex")).to.equal("facf1e3e6c74916203b7f714ca100d4d60604f0917696d0f09330f82f52bed1a");
        });
      });
    }
  });

  describe("pubkey", function() {
    it("should encode and decode pubkey v2", function() {
      return pubkey.encodeAsync({
        ttl: 123,
        from: from,
        to: "BM-onhypnh1UMhbQpmvdiPuG6soLLytYJAfH",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return pubkey.decodeAsync(buf, skipPow);
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(123);
        expect(res.type).to.equal(object.PUBKEY);
        expect(res.version).to.equal(2);
        expect(res.stream).to.equal(1);
        expect(res.behavior.get(PubkeyBitfield.DOES_ACK)).to.be.true;
        expect(bufferEqual(res.signPublicKey, signPublicKey)).to.be.true;
        expect(bufferEqual(res.encPublicKey, encPublicKey)).to.be.true;
        expect(res.length).to.equal(132);
      });
    });

    it("should encode and decode pubkey v3", function() {
      return pubkey.encodeAsync({
        ttl: 456,
        from: from,
        to: "BM-2D8Jxw5yiepaQqxrx43iPPNfRqbvWoJLoU",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return pubkey.decodeAsync(buf, skipPow);
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(456);
        expect(res.type).to.equal(object.PUBKEY);
        expect(res.version).to.equal(3);
        expect(res.stream).to.equal(1);
        expect(res.behavior.get(PubkeyBitfield.DOES_ACK)).to.be.true;
        expect(bufferEqual(res.signPublicKey, signPublicKey)).to.be.true;
        expect(bufferEqual(res.encPublicKey, encPublicKey)).to.be.true;
        expect(res.nonceTrialsPerByte).to.equal(1000);
        expect(res.payloadLengthExtraBytes).to.equal(1000);
        expect(Buffer.isBuffer(res.signature)).to.be.true;
      });
    });

    it("should encode and decode pubkey v4", function() {
      return pubkey.encodeAsync({ttl: 789, from: from, to: from, skipPow: true})
      .then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return pubkey.decodeAsync(buf, {needed: from, skipPow: true});
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(789);
        expect(res.type).to.equal(object.PUBKEY);
        expect(res.version).to.equal(4);
        expect(res.stream).to.equal(1);
        expect(res.behavior.get(PubkeyBitfield.DOES_ACK)).to.be.true;
        expect(bufferEqual(res.signPublicKey, signPublicKey)).to.be.true;
        expect(bufferEqual(res.encPublicKey, encPublicKey)).to.be.true;
        expect(res.nonceTrialsPerByte).to.equal(1000);
        expect(res.payloadLengthExtraBytes).to.equal(1000);
        expect(Buffer.isBuffer(res.signature)).to.be.true;
        expect(bufferEqual(res.tag, from.getTag())).to.be.true;
      });
    });

    if (allTests) {
      it("should encode and decode pubkey with nonce", function() {
        this.timeout(300000);
        return pubkey.encodePayloadAsync({ttl: 789, from: from, to: from})
        .then(function(payload) {
          expect(POW.check({ttl: 789, payload: payload})).to.be.true;;
          return pubkey.decodePayloadAsync(payload, {needed: from});
        }).then(function(res) {
          expect(res.ttl).to.be.at.most(789);
          expect(bufferEqual(res.tag, from.getTag())).to.be.true;
        });
      });
    }
  });

  describe("msg", function() {
    it("should encode and decode msg", function() {
      return msg.encodeAsync({
        ttl: 111,
        from: from,
        to: from,
        message: "test",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return msg.decodeAsync(buf, {identities: [from], skipPow: true});
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(111);
        expect(res.type).to.equal(object.MSG);
        expect(res.version).to.equal(1);
        expect(res.stream).to.equal(1);
        expect(res.senderVersion).to.equal(4);
        expect(res.senderStream).to.equal(1);
        expect(res.behavior.get(PubkeyBitfield.DOES_ACK)).to.be.true;
        expect(bufferEqual(res.signPublicKey, signPublicKey)).to.be.true;
        expect(bufferEqual(res.encPublicKey, encPublicKey)).to.be.true;
        expect(res.nonceTrialsPerByte).to.equal(1000);
        expect(res.payloadLengthExtraBytes).to.equal(1000);
        expect(bufferEqual(res.ripe, from.ripe)).to.be.true;
        expect(res.encoding).to.equal(msg.TRIVIAL);
        expect(res.message).to.equal("test");
        expect(res).to.not.have.property("subject");
        expect(Buffer.isBuffer(res.signature)).to.be.true;
      });
    });

    it("should encode and decode msg for address v2", function() {
      return msg.encodeAsync({
        ttl: 111,
        from: fromV2,
        to: fromV2,
        message: "test",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return msg.decodeAsync(buf, {identities: [fromV2], skipPow: true});
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(111);
        expect(res.type).to.equal(object.MSG);
        expect(res.version).to.equal(1);
        expect(res.stream).to.equal(1);
        expect(res.senderVersion).to.equal(2);
        expect(res.senderStream).to.equal(1);
        expect(res.behavior.get(PubkeyBitfield.DOES_ACK)).to.be.true;
        expect(bufferEqual(res.signPublicKey, signPublicKey)).to.be.true;
        expect(bufferEqual(res.encPublicKey, encPublicKey)).to.be.true;
        expect(res).to.not.have.property("nonceTrialsPerByte");
        expect(res).to.not.have.property("payloadLengthExtraBytes");
        expect(bufferEqual(res.ripe, fromV2.ripe)).to.be.true;
        expect(res.encoding).to.equal(msg.TRIVIAL);
        expect(res.message).to.equal("test");
        expect(res).to.not.have.property("subject");
        expect(Buffer.isBuffer(res.signature)).to.be.true;
      });
    });

    it("shouldn't decode msg without identities", function(done) {
      return msg.encodeAsync({
        ttl: 111,
        from: from,
        to: from,
        message: "test",
        skipPow: true,
      }).then(function(buf) {
        return msg.decodeAsync(buf, {identities: [], skipPow: true});
      }).catch(function(err) {
        expect(err.message).to.match(/with given identities/i);
        done();
      });
    });

    it("should encode and decode SIMPLE msg", function() {
      return msg.encodeAsync({
        ttl: 111,
        from: from,
        to: from,
        encoding: msg.SIMPLE,
        subject: "Тема",
        message: "Сообщение",
        skipPow: true,
      }).then(function(buf) {
        return msg.decodeAsync(buf, {identities: [from], skipPow: true});
      }).then(function(res) {
        expect(res.encoding).to.equal(msg.SIMPLE);
        expect(res.subject).to.equal("Тема");
        expect(res.message).to.equal("Сообщение");
      });
    });

    it("shouldn't encode too big msg", function(done) {
      return msg.encodeAsync({
        ttl: 111,
        from: from,
        to: from,
        message: Buffer(300000),
        skipPow: true,
      }).catch(function(err) {
        expect(err.message).to.match(/too big/i);
        done();
      });
    });

    if (allTests) {
      it("should encode and decode msg with nonce", function() {
        this.timeout(300000);
        return msg.encodePayloadAsync({
          ttl: 111,
          from: from,
          to: from,
          message: "test",
        }).then(function(payload) {
          expect(POW.check({ttl: 111, payload: payload})).to.be.true;;
          return msg.decodePayloadAsync(payload, {identities: from});
        }).then(function(res) {
          expect(res.ttl).to.be.at.most(111);
          expect(res.message).to.equal("test");
        });
      });
    }
  });

  describe("broadcast", function() {
    it("should encode and decode broadcast v4", function() {
      return broadcast.encodeAsync({
        ttl: 987,
        from: fromV3,
        message: "test",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return broadcast.decodeAsync(buf, {subscriptions: fromV3, skipPow: true});
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(987);
        expect(res.type).to.equal(object.BROADCAST);
        expect(res.version).to.equal(4);
        expect(res.stream).to.equal(1);
        expect(res.senderVersion).to.equal(3);
        expect(res.senderStream).to.equal(1);
        expect(res.behavior.get(PubkeyBitfield.DOES_ACK)).to.be.true;
        expect(bufferEqual(res.signPublicKey, signPublicKey)).to.be.true;
        expect(bufferEqual(res.encPublicKey, encPublicKey)).to.be.true;
        expect(res.nonceTrialsPerByte).to.equal(1000);
        expect(res.payloadLengthExtraBytes).to.equal(1000);
        expect(res.encoding).to.equal(msg.TRIVIAL);
        expect(res.message).to.equal("test");
        expect(res).to.not.have.property("subject");
        expect(Buffer.isBuffer(res.signature)).to.be.true;
      });
    });

    it("should encode and decode broadcast v4 for address v2", function() {
      return broadcast.encodeAsync({
        ttl: 999,
        from: fromV2,
        message: "test",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return broadcast.decodeAsync(buf, {subscriptions: fromV2, skipPow: true});
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(999);
        expect(res.type).to.equal(object.BROADCAST);
        expect(res.version).to.equal(4);
        expect(res.stream).to.equal(1);
        expect(res.senderVersion).to.equal(2);
        expect(res.senderStream).to.equal(1);
        expect(res.behavior.get(PubkeyBitfield.DOES_ACK)).to.be.true;
        expect(bufferEqual(res.signPublicKey, signPublicKey)).to.be.true;
        expect(bufferEqual(res.encPublicKey, encPublicKey)).to.be.true;
        expect(res).to.not.have.property("nonceTrialsPerByte");
        expect(res).to.not.have.property("payloadLengthExtraBytes");
        expect(res.encoding).to.equal(msg.TRIVIAL);
        expect(res.message).to.equal("test");
        expect(res).to.not.have.property("subject");
        expect(Buffer.isBuffer(res.signature)).to.be.true;
      });
    });

    it("should encode and decode broadcast v5", function() {
      return broadcast.encodeAsync({
        ttl: 101,
        from: from,
        message: "キタ━━━(゜∀゜)━━━!!!!!",
        skipPow: true,
      }).then(function(buf) {
        expect(message.decode(buf).command).to.equal("object");
        return broadcast.decodeAsync(buf, {subscriptions: [from], skipPow: true});
      }).then(function(res) {
        expect(res.ttl).to.be.at.most(101);
        expect(res.type).to.equal(object.BROADCAST);
        expect(res.version).to.equal(5);
        expect(res.stream).to.equal(1);
        expect(res.senderVersion).to.equal(4);
        expect(res.senderStream).to.equal(1);
        expect(res.behavior.get(PubkeyBitfield.DOES_ACK)).to.be.true;
        expect(bufferEqual(res.signPublicKey, signPublicKey)).to.be.true;
        expect(bufferEqual(res.encPublicKey, encPublicKey)).to.be.true;
        expect(res.nonceTrialsPerByte).to.equal(1000);
        expect(res.payloadLengthExtraBytes).to.equal(1000);
        expect(res.encoding).to.equal(msg.TRIVIAL);
        expect(res.message).to.equal("キタ━━━(゜∀゜)━━━!!!!!");
        expect(res).to.not.have.property("subject");
        expect(Buffer.isBuffer(res.signature)).to.be.true;
      });
    });

    it("shouldn't decode broadcast without subscriptions", function(done) {
      return broadcast.encodeAsync({
        ttl: 101,
        from: from,
        message: "test",
        skipPow: true,
      }).then(function(buf) {
        return broadcast.decodeAsync(buf, {
          subscriptions: [fromV3],
          skipPow: true,
        });
      }).catch(function(err) {
        expect(err.message).to.match(/not interested/i);
        done();
      });
    });

    it("shouldn't encode too big broadcast", function(done) {
      return broadcast.encodeAsync({
        ttl: 101,
        from: from,
        message: Buffer(300000),
        skipPow: true,
      }).catch(function(err) {
        expect(err.message).to.match(/too big/i);
        done();
      });
    });

    if (allTests) {
      it("should encode and decode broadcast with nonce", function() {
        this.timeout(300000);
        return broadcast.encodePayloadAsync({
          ttl: 101,
          from: from,
          message: "test",
        }).then(function(payload) {
          expect(POW.check({ttl: 101, payload: payload})).to.be.true;;
          return broadcast.decodePayloadAsync(payload, {subscriptions: from});
        }).then(function(res) {
          expect(res.ttl).to.be.at.most(101);
          expect(res.message).to.equal("test");
        });
      });
    }
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

describe("POW", function() {
  it("should calculate target", function() {
    expect(POW.getTarget({ttl: 2418984, payloadLength: 636, nonceTrialsPerByte: 1000, payloadLengthExtraBytes: 1000})).to.equal(297422525267);
    expect(POW.getTarget({ttl: 86400, payloadLength: 636})).to.equal(4863575534951);
  });

  it("should check a POW", function() {
    expect(POW.check({nonce: 21997550, target: 297422525267, initialHash: Buffer("8ff2d685db89a0af2e3dbfd3f700ae96ef4d9a1eac72fd778bbb368c7510cddda349e03207e1c4965bd95c6f7265e8f1a481a08afab3874eaafb9ade09a10880", "hex")})).to.be.true;
    expect(POW.check({nonce: 3122437, target: 4864647698763, initialHash: Buffer("8ff2d685db89a0af2e3dbfd3f700ae96ef4d9a1eac72fd778bbb368c7510cddda349e03207e1c4965bd95c6f7265e8f1a481a08afab3874eaafb9ade09a10880", "hex")})).to.be.true;
    expect(POW.check({nonce: 3122436, target: 4864647698763, initialHash: Buffer("8ff2d685db89a0af2e3dbfd3f700ae96ef4d9a1eac72fd778bbb368c7510cddda349e03207e1c4965bd95c6f7265e8f1a481a08afab3874eaafb9ade09a10880", "hex")})).to.be.false;
  });

  it("should reject promise on bad POW arguments", function(done) {
    POW.doAsync({target: 123, initialHash: {}}).catch(function() {
      POW.doAsync({target: 123, initialHash: Buffer("test")}).catch(function() {
        POW.doAsync({poolSize: -1, target: 123, initialHash: Buffer(64)})
        .catch(function() {
          done();
        });
      });
    });
  });

  if (allTests) {
    it("should do a POW", function() {
      this.timeout(300000);
      var target = typeof window === "undefined" ? 297422525267 : 10688385392246;
      var initialHash = Buffer("8ff2d685db89a0af2e3dbfd3f700ae96ef4d9a1eac72fd778bbb368c7510cddda349e03207e1c4965bd95c6f7265e8f1a481a08afab3874eaafb9ade09a10880", "hex");
      return POW.doAsync({target: target, initialHash: initialHash})
      .then(function(nonce) {
        // FIXME(Kagami): Chromium behaves very strangely on Travis CI:
        // computed nonces may vary in a big range (since target is
        // simple, there are a lot of valid nonces). Probably because
        // some spawned web workers get blocked for some reason.
        if (typeof window === "undefined") {
          expect(nonce).to.equal(21997550);
        }
        expect(POW.check({
          nonce: nonce,
          target: target,
          initialHash: initialHash,
        })).to.be.true;
      });
    });
  }
});

describe("High-level classes", function() {
  // FIXME(Kagami): Add more fail tests.
  describe("Address", function() {
    it("should decode Bitmessage address", function() {
      var addr = Address.decode("BM-2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
      expect(addr.version).to.equal(4);
      expect(addr.stream).to.equal(1);
      expect(addr.ripe.toString("hex")).to.equal("003ab6655de4bd8c603eba9b00dd5970725fdd56");
    });

    it("should decode Bitmessage address badly formatted", function() {
      var addr = Address.decode("  2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z ");
      expect(addr.version).to.equal(4);
      expect(addr.stream).to.equal(1);
      expect(addr.ripe.toString("hex")).to.equal("003ab6655de4bd8c603eba9b00dd5970725fdd56");
    });

    it("should allow to create random Bitmessage address", function() {
      this.timeout(60000);
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

    it("should allow to create Bitmessage address from passphrase", function() {
      this.timeout(60000);
      var addr = Address.fromPassphrase({passphrase: "test"});
      expect(addr.version).to.equal(4);
      expect(addr.stream).to.equal(1);
      expect(bufferEqual(addr.signPrivateKey, WIF.decode("5JY1CFeeyN4eyfL35guWAuUqu5VLmd7LojtkNP6wmt5msZxxZ57"))).to.be.true;
      expect(bufferEqual(addr.encPrivateKey, WIF.decode("5J1oDgZDicNhUgbfzBDQqi2m5jUPnDrfZinnTqEEEaLv63jVFTM"))).to.be.true;
      expect(addr.ripe.toString("hex")).to.equal("00ac14944b00decea5628eb40d0ff4b0f9ee9eca");
      expect(addr.encode()).to.equal("BM-2cWFkyuXXFw6d393RGnin2RpSXj8wxtt6F");
    });

    it("should accept string in Address.fromPassphrase", function() {
      this.timeout(60000);
      var addr = Address.fromPassphrase("test");
      expect(addr.version).to.equal(4);
      expect(addr.stream).to.equal(1);
      expect(bufferEqual(addr.signPrivateKey, WIF.decode("5JY1CFeeyN4eyfL35guWAuUqu5VLmd7LojtkNP6wmt5msZxxZ57"))).to.be.true;
      expect(bufferEqual(addr.encPrivateKey, WIF.decode("5J1oDgZDicNhUgbfzBDQqi2m5jUPnDrfZinnTqEEEaLv63jVFTM"))).to.be.true;
      expect(addr.ripe.toString("hex")).to.equal("00ac14944b00decea5628eb40d0ff4b0f9ee9eca");
      expect(addr.encode()).to.equal("BM-2cWFkyuXXFw6d393RGnin2RpSXj8wxtt6F");
    });

    it("should calculate tag", function() {
      var addr = Address.decode("2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
      expect(addr.getTag().toString("hex")).to.equal("facf1e3e6c74916203b7f714ca100d4d60604f0917696d0f09330f82f52bed1a");
    });

    it("should calculate a private key to decrypt pubkey object", function() {
      var addr = Address.decode("BM-2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
      expect(addr.getPubkeyPrivateKey().toString("hex")).to.equal("15e516173769dc87d4a8e8ed90200362fa58c0228bb2b70b06f26c089a9823a4");
    });

    it("should calculate a public key to encrypt pubkey object", function() {
      var addr = Address.decode("BM-2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
      expect(addr.getPubkeyPublicKey().toString("hex")).to.equal("04ee196be97db61886beeec9ebc2c28b7d4cafbc407c31d8aac2f867068f727874e2d305ba970bd09a951aa2cde52b66061a5a8e709cda1125635a97e1c7b85ab4");
    });

    it("should calculate a private key to decrypt broadcast v4", function() {
      var addr = Address.decode("   2D8Jxw5yiepaQqxrx43iPPNfRqbvWoJLoU   ");
      expect(addr.version).to.equal(3);
      expect(addr.getBroadcastPrivateKey().toString("hex")).to.equal("664420eaed1b6b3208fc04905c2f6ca758594c537eb5a08f2f0c2bbe6f07fb44");
    });

    it("should calculate a public key to encrypt broadcast v4", function() {
      var addr = Address.decode("   2D8Jxw5yiepaQqxrx43iPPNfRqbvWoJLoU   ");
      expect(addr.version).to.equal(3);
      expect(addr.getBroadcastPublicKey().toString("hex")).to.equal("04da633350cf2ef8194b83ae028555971df56a64948940693e54b8b4c2597b8f9e833ac1285b37487121c271346fb29684e723a992aeb37b20962406ccade6c8d3");
    });

    it("should calculate a private key to decrypt broadcast v5", function() {
      var addr = Address.decode("BM-2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
      expect(addr.version).to.equal(4);
      expect(addr.getBroadcastPrivateKey().toString("hex")).to.equal("15e516173769dc87d4a8e8ed90200362fa58c0228bb2b70b06f26c089a9823a4");
    });

    it("should calculate a public key to encrypt broadcast v5", function() {
      var addr = Address.decode("BM-2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
      expect(addr.version).to.equal(4);
      expect(addr.getBroadcastPublicKey().toString("hex")).to.equal("04ee196be97db61886beeec9ebc2c28b7d4cafbc407c31d8aac2f867068f727874e2d305ba970bd09a951aa2cde52b66061a5a8e709cda1125635a97e1c7b85ab4");
    });

    it("should allow to decode Address instance", function() {
      var addr = Address.decode("2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
      expect(addr.ripe.toString("hex")).to.equal("003ab6655de4bd8c603eba9b00dd5970725fdd56");
      expect(Address.decode(addr)).to.equal(addr);
    });

    it("should provide setters for keys and ripe", function() {
      var addr = Address();
      expect(function(){addr.ripe}).to.throw(Error);
      addr.signPrivateKey = Buffer("71c95d26c716a5e85e9af9efe26fb5f744dc98005a13d05d23ee92c77e038d9f", "hex");
      expect(addr.signPublicKey.toString("hex")).to.equal("042d391543f574608cbcdfd12a37cc4c74dd36e54510b13a6a1d8b7b1498fb96c92873d33ca17586dace7f5ad0f4532a954061ac06bc5230aed9c8374072546571");
      expect(function(){addr.ripe}).to.throw(Error);
      addr.encPrivateKey = Buffer("9f9969c93c2d186787a7653f70e49be34c03c4a853e6ad0c867db0946bc433c6", "hex");
      expect(addr.encPublicKey.toString("hex")).to.equal("04c6ed1b56f2da97fec1b762d43364566faf082c1e4918ae1dbb41757cad41b03b2cc5087f341414e63f6eee72a1fbf0b5f346a1bb3ba944cad204ca597db2bfc8");
      expect(addr.ripe.toString("hex")).to.equal("003ab6655de4bd8c603eba9b00dd5970725fdd56");
      expect(addr.getShortRipe().toString("hex")).to.equal("3ab6655de4bd8c603eba9b00dd5970725fdd56");
      addr.encPrivateKey = Buffer("009969c93c2d186787a7653f70e49be34c03c4a853e6ad0c867db0946bc433c6", "hex");
      expect(addr.getShortRipe().toString("hex")).to.equal("69617ddb1946dc327cadffcf33889fed587fc1e7");
    });

    it("should implement isAddress method", function() {
      var addr = Address();
      expect(Address.isAddress(addr)).to.be.true;
      expect(Address.isAddress(null)).to.be.false;
      expect(Address.isAddress({})).to.be.false;
    });

    it("should implement clone method", function() {
      var addr = Address.decode("BM-2cTux3PGRqHTEH6wyUP2sWeT4LrsGgy63z");
      expect(addr.version).to.equal(4);
      expect(addr.stream).to.equal(1);
      var addr2 = addr.clone();
      expect(addr2.version).to.equal(4);
      expect(addr2.stream).to.equal(1);
      addr2.version = 3;
      addr2.stream = 2;
      expect(addr.getTag().toString("hex")).to.equal("facf1e3e6c74916203b7f714ca100d4d60604f0917696d0f09330f82f52bed1a");
      expect(addr2.getTag().toString("hex")).to.equal("d6487aaea3d2d022d80abbce2605089523ba2b516b81c03545f19a5c85f15fa2");

      var addr3 = Address({
        signPrivateKey: Buffer("71c95d26c716a5e85e9af9efe26fb5f744dc98005a13d05d23ee92c77e038d9f", "hex"),
        encPrivateKey: Buffer("9f9969c93c2d186787a7653f70e49be34c03c4a853e6ad0c867db0946bc433c6", "hex"),
      });
      var addr4 = addr3.clone();
      expect(addr4.signPrivateKey.toString("hex")).to.equal("71c95d26c716a5e85e9af9efe26fb5f744dc98005a13d05d23ee92c77e038d9f");
      expect(addr4.encPrivateKey.toString("hex")).to.equal("9f9969c93c2d186787a7653f70e49be34c03c4a853e6ad0c867db0946bc433c6");
    });

    // FIXME(Kagami): Don't run it in browser currently because it's
    // very slow. This need to be fixed.
    if (allTests && typeof window === "undefined") {
      it("should allow to generate shorter address", function() {
        this.timeout(300000);
        var addr = Address.fromRandom({ripeLength: 18});
        var ripe = addr.getShortRipe();
        expect(ripe.length).to.be.at.most(18);
      });
    }
  });

  describe("UserAgent", function() {
    var pybm = {name: "PyBitmessage", version: "0.4.4"};
    var bnode = {name: "bitchan-node", version: "0.0.1"};
    var bweb = {name: "bitchan-web"};

    it("should decode and parse", function() {
      var ua = var_str.encode("/cBitmessage:0.2(iPad; U; CPU OS 3_2_1)/AndroidBuild:0.8/");
      var res = UserAgent.decode(ua);
      expect(UserAgent.parse(res.str)).to.deep.equal([
        {name: "cBitmessage", version: "0.2", comments: "iPad; U; CPU OS 3_2_1"},
        {name: "AndroidBuild", version: "0.8"},
      ]);
      expect(res.length).to.equal(58);
      expect(res.rest.toString("hex")).to.equal("");
    });

    it("should encode", function() {
      var ua = UserAgent.encode([pybm]);
      var res = UserAgent.decode(ua);
      expect(res.str).to.equal("/PyBitmessage:0.4.4/");
      expect(UserAgent.parse(res.str)).to.deep.equal([pybm]);
      expect(res.length).to.equal(21);
      expect(res.rest.toString("hex")).to.equal("");

      ua = UserAgent.encode([{name: "test", "comments": "linux"}]);
      expect(UserAgent.decode(ua).str).to.equal("/test:0.0.0(linux)/");
    });

    it("should encode bitmessage's user agent", function() {
      var res = UserAgent.decode(UserAgent.encodeSelf())
      var software = UserAgent.parse(res.str);
      expect(software[0].name).to.equal("bitmessage");
      expect(software[0]).to.have.property("version");

      res = UserAgent.decode(UserAgent.encodeSelfWith([bnode, bweb]));
      software = UserAgent.parse(res.str);
      expect(software[0].name).to.equal("bitmessage");
      expect(software[1]).to.deep.equal(bnode);
      expect(software[2].name).to.equal(bweb.name);
      expect(software[2].version).to.equal("0.0.0");
    });

    it("should accept raw user agent string on encode", function() {
      var enc = UserAgent.encode("/test:0.0.1/");
      var software = UserAgent.parse(UserAgent.decode(enc).str);
      expect(software).to.deep.equal([{name: "test", version: "0.0.1"}]);
    });

    it("should parse empty/incorrect user agent into empty list", function() {
      expect(UserAgent.parse("").length).to.equal(0);
      expect(UserAgent.parse("test").length).to.equal(0);
      expect(UserAgent.parse("/test").length).to.equal(0);
      expect(UserAgent.parse("test/").length).to.equal(0);
    });

    it("should accept raw Buffer on encode", function() {
      var enc = UserAgent.encodeSelfWith("test:0.0.1");
      enc = UserAgent.encode(enc);
      var software = UserAgent.parse(UserAgent.decode(enc).str);
      expect(software[0].name).to.equal("bitmessage");
      expect(software[1]).to.deep.equal({name: "test", version: "0.0.1"});
    });

  });
});
