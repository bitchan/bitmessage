/**
 * Working with Bitmessage addresses.
 * @module bitmessage/address
 */

"use strict";

var assert = require("assert");
var bufferEqual = require("buffer-equal");
var bs58 = require("bs58");
var varint = require("./varint");
var bmcrypto = require("./crypto");

/**
 * Parse Bitmessage Base58 encoded address (with or without `BM-`
 * prefix) into address object.
 */
exports.decode = function(str) {
  str = str.trim();
  if (str.slice(0, 3) === "BM-") {
    str = str.slice(3);
  }

  var bytes;
  try {
    bytes = bs58.decode(str);
  } catch(e) {
    return Promise.reject(e);
  }

  // Checksum validating.
  var data = new Buffer(bytes.slice(0, -4));
  var checksum = new Buffer(bytes.slice(-4));
  return bmcrypto.sha512(data).then(bmcrypto.sha512).then(function(dhash) {
    assert(bufferEqual(dhash.slice(0, 4), checksum), "Bad checkum");

    var decoded = varint.decode(data);
    var version = decoded.value;
    assert(version <= 4, "Version too high");
    assert(version >= 1, "Version too low");

    data = decoded.rest;
    decoded = varint.decode(data);
    var stream = decoded.value;

    var ripe = decoded.rest;
    var ripelen = ripe.length;
    switch (version) {
      case 1:
        assert(ripelen === 20);
        break;
      case 2:
      case 3:
        assert(ripelen >= 18, "Ripe too short");
        assert(ripelen <= 20, "Ripe too long");
        break;
      case 4:
        assert(ripelen >= 4, "Ripe too short");
        assert(ripelen <= 20, "Ripe too long");
        assert(ripe[0] !== 0, "Ripe encode error");
        break;
    }

    // Prevent extra allocation. God, kill me please for premature
    // optimizations.
    if (ripelen < 20) {
      var zeroes = new Buffer(Array(20 - ripelen));
      ripe = Buffer.concat([zeroes, ripe]);
    }
    return {version: version, stream: stream, ripe: ripe};
  });
};
