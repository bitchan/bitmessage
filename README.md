# bitmessage [![Build Status](https://travis-ci.org/bitchan/bitmessage.svg?branch=master)](https://travis-ci.org/bitchan/bitmessage)

[![NPM](https://nodei.co/npm/bitmessage.png)](https://www.npmjs.com/package/bitmessage)

JavaScript Bitmessage library for both browserify and node. The goal of this project is to implement Bitmessage protocol v3 for both platforms at the maximum possible level (we still can't create TCP connections or listen for incoming connections in the Browser but the Proof of work and crypto is fully doable).

Public library API is currently in alpha stage, breaking changes are very likely to happen.

API documentation is available [here](https://bitchan.github.io/bitmessage/docs/).

## References

* [Bitmessage wiki](https://bitmessage.org/wiki/Main_Page)
* [Protocol specification](https://bitmessage.org/wiki/Protocol_specification)
* [Whitepaper](https://bitmessage.org/bitmessage.pdf)

## Feature matrix

- [x] Crypto
  - [x] SHA-1
  - [x] SHA-256
  - [x] SHA-512
  - [x] RIPEMD-160
  - [x] PRNG
  - [x] ECC keys handling
  - [x] ECDSA
  - [x] ECIES
- [x] Common structures
  - [x] message
  - [x] object
  - [x] var_int
  - [x] var_str
  - [x] var_int_list
  - [x] net_addr
  - [x] inv_vect
  - [x] encrypted
  - [x] service features
  - [x] pubkey features
- [x] Message types
  - [x] version
  - [x] addr
  - [x] inv
  - [x] getdata
  - [x] error
- [x] Object types
  - [x] getpubkey
  - [x] pubkey
  - [x] msg
  - [x] broadcast
- [x] WIF
- [x] POW
- [x] High-level classes
  - [x] Address
  - [x] UserAgent
- [ ] Network transports
  - [x] TCP (Node.js only)
  - [x] WebSocket
  - [ ] WebRTC
- [ ] PyBitmessage configs parsing
  - [ ] keys.dat
  - [ ] knownnodes.dat
  - [ ] messages.dat

## Usage

### Address

```js
var Address = require("bitmessage").Address;

// Generate a new random Bitmessage identity.
var addr1 = Address.fromRandom();
console.log("New random Bitmessage address:", addr1.encode());

// Or create it from passphrase.
var addr2 = Address.fromPassphrase("test");
console.log("Deterministic Bitmessage address:", addr2.encode());
```

### Structures

```js
var structs = require("bitmessage").structs;

var encoded = Buffer.concat([
  structs.var_int.encode(4),
  Buffer("test"),
  structs.var_str.encode("test2"),
  structs.var_int_list.encode([1, 2, 3]),
]);

var decoded1 = structs.var_str.decode(encoded);
console.log(decoded1.str);  // test
var decoded2 = structs.var_str.decode(decoded1.rest);
console.log(decoded2.str);  // test2
var decoded3 = structs.var_int.decode(decoded2.rest);
console.log(decoded3.value);  // 3
var decoded4 = structs.var_int_list.decode(decoded2.rest);
console.log(decoded4.list);  // [1, 2, 3]
```

### Messages

```js
var structs = require("bitmessage").structs;
var messages = require("bitmessage").messages;

// Simple encoding and decoding:
var vermsg = messages.version.encode({
  nonce: Buffer(8),  // Hack detection connection to self
  remoteHost: "1.1.1.1",
  remotePort: 8444,
});
console.log(messages.version.decode(vermsg).remoteHost);  // 1.1.1.1

// Low-level encoding and decoding:
var addrPayload = messages.addr.encodePayload([
  {host: "2.2.2.2", port: 28444},
]);
var addrmsg = structs.message.encode("addr", addrPayload);
var decoded = structs.message.decode(addrmsg);
console.log(decoded.command);  // addr
var payload = decoded.payload;
var decodedPayload = messages.addr.decodePayload(payload);
console.log(decodedPayload.addrs[0].host);  // 2.2.2.2

// Encode with empty payload:
var verackmsg = structs.message.encode("verack");
console.log(structs.message.decode(verackmsg).command);  // verack
```

### Network

```js
var messages = require("bitmessage").messages;
var TcpTransport = require("bitmessage/net/tcp");

var tcp = new TcpTransport({
  dnsSeeds: [["bootstrap8444.bitmessage.org", 8444]],
});

tcp.bootstrap().then(function(nodes) {
  var remoteHost = nodes[0][0];
  var remotePort = nodes[0][1];
  console.log("Connecting to", nodes[0]);
  tcp.connect(remotePort, remoteHost);
});

tcp.on("established", function() {
  console.log("Connection established");

  tcp.on("message", function(command, payload) {
    console.log("Got new", command, "message");
    var decoded;
    if (command === "addr") {
      decoded = messages.addr.decodePayload(payload);
      console.log("Got", decoded.addrs.length, "node addresses");
    }
  });
});
```

## License

bitmessage - JavaScript Bitmessage library

Written in 2014-2015 by Kagami Hiiragi <kagami@genshiken.org>

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
