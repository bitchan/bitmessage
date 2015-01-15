# bitmessage [![Build Status](https://travis-ci.org/bitchan/bitmessage.svg?branch=master)](https://travis-ci.org/bitchan/bitmessage)

JavaScript Bitmessage library for both browserify and node. The goal of this project is to implement Bitmessage protocol v3 for both platforms at the maximum possible level (we still can't create TCP connections or listen for incoming connections in the Browser but the Proof of work and crypto is fully doable).

Public library API is currently in alpha stage, breaking changes are very likely to happen.

API documentation is available [here](https://bitchan.github.io/bitmessage/docs/).

## References

* [Bitmessage wiki](https://bitmessage.org/wiki/Main_Page)
* [Protocol specification](https://bitmessage.org/wiki/Protocol_specification)
* [Whitepaper](https://bitmessage.org/bitmessage.pdf)

## Feature matrix (both Browser and Node)

- [x] crypto
  - [x] SHA-512
  - [x] SHA-256
  - [x] RIPEMD-160
  - [x] PRNG
  - [x] ECC keys manipulation
  - [x] ECDSA
  - [x] ECDH
  - [x] ECIES
  - [x] AES-256-CBC
  - [x] HMAC-SHA-256
- [x] Common structures
  - [x] message
  - [x] var_int
  - [x] var_str
  - [x] var_int_list
  - [x] net_addr
  - [x] encrypted
  - [x] message encodings
  - [x] service features
  - [x] pubkey features
- [ ] Message types
  - [x] version
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
- [x] POW
- [ ] High-level classes
  - [ ] Address
    - [x] encode
    - [x] decode
    - [x] getRipe
    - [x] fromRandom
    - [ ] fromPassphrase
  - [x] UserAgent
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
// Generate a new random Bitmessage identity.
var Address = require("bitmessage").Address;
var addr = Address.fromRandom();
console.log("New random Bitmessage address:", addr.encode());
```

## License

bitmessage - JavaScript Bitmessage library

Written in 2014 by Kagami Hiiragi <kagami@genshiken.org>

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
