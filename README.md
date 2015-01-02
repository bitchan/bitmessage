# bitmessage [![Build Status](https://travis-ci.org/bitchan/bitmessage.svg?branch=master)](https://travis-ci.org/bitchan/bitmessage)

JavaScript Bitmessage library for both browserify and node. The goal of this project is to implement Bitmessage protocol v3 for both platforms at the maximum possible level (we still can't create TCP connections or listen for incoming connections in the Browser but the Proof of work and crypto is fully doable).

Public library API is currently in alpha stage, breaking changes are very likely to happen.

API documentation is available [here](https://bitchan.github.io/bitmessage/docs/).

## References

* [Project wiki](https://bitmessage.org/wiki/Main_Page)
* [Protocol specification](https://bitmessage.org/wiki/Protocol_specification)
* [Whitepaper](https://bitmessage.org/bitmessage.pdf)

## Implementation details

With the help of browserify `bitmessage` provides different implementations for Browser and Node.js with the same API. Because WebCryptoAPI defines asynchronous promise-driven API, implementation for Node needs to use promises too.

* Use Node.js crypto module/library bindings where possible
* Use WebCryptoAPI where possible
* Promise-driven API

## Feature matrix (both Browser and Node)

- [ ] crypto
  - [x] SHA-512
  - [x] SHA-256
  - [x] RIPEMD-160
  - [x] PRNG
  - [x] ECC keys manipulation
  - [x] ECDSA
  - [ ] ECDH
  - [ ] ECIES
  - [ ] AES-256-CBC
  - [ ] HMAC-SHA-256
- [ ] Common structures
  - [ ] message
  - [x] var_int
  - [x] var_str
  - [x] var_int_list
  - [ ] net_addr
  - [ ] inv_vect
  - [ ] encrypted
  - [ ] unencrypted
  - [ ] encoding
  - [ ] bitfield
- [ ] Message types
  - [ ] version
  - [ ] verack
  - [ ] addr
  - [ ] inv
  - [ ] getdata
  - [ ] error
  - [ ] object
- [ ] Object types
  - [ ] getpubkey
  - [ ] pubkey
  - [ ] msg
  - [ ] broadcast
- [x] WIF
- [ ] POW
- [ ] High-level classes
  - [ ] Address
    - [x] encode
    - [x] decode
    - [x] getRipe
    - [x] fromRandom
    - [ ] fromPassphrase
  - [ ] Message
    - [ ] encrypt
    - [ ] decrypt
- [ ] Parse PyBitmessage configs
  - [ ] keys.dat
  - [ ] knownnodes.dat
  - [ ] messages.dat

## Feature matrix (Node.js only)

- [ ] Network
  - [ ] Bootstrap
  - [ ] Connect to the network
  - [ ] Accept connections

## Usage

```js
// Generating a new Bitmessage identity.
var Address = require("bitmessage").Address;
Address.fromRandom().then(function(addr) {
  addr.encode().then(function(str) {
    console.log("New random Bitmessage address:", str);
  });
});
```

## License

bitmessage - JavaScript Bitmessage library

Written in 2014 by Kagami Hiiragi <kagami@genshiken.org>

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
