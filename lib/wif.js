/**
 * Implement WIF encoding/decoding.
 * Reference: <https://en.bitcoin.it/wiki/Wallet_import_format>
 * @module bitmessage/wif
 */

"use strict";

require("es6-promise").polyfill();
var assert = require("assert");
var bufferEqual = require("buffer-equal");
var bs58 = require("bs58");
var bmcrypto = require("./crypto");

// Compute the WIF checksum for the given data.
function getchecksum(data) {
  return bmcrypto.sha256(data).then(bmcrypto.sha256).then(function(dhash) {
    return dhash.slice(0, 4);
  });
}

/**
 * Decode WIF encoded private key.
 * @param {string} input - Input data
 * @param {Promise.<Buffer,undefined>} A promise than contain private
 * key when fulfilled
 */
exports.decode = function(input) {
  var bytes;
  try {
    bytes = bs58.decode(input);
    assert(bytes[0] === 0x80, "Bad WIF");
  } catch(e) {
    return Promise.reject(e);
  }
  var data = new Buffer(bytes.slice(0, -4));
  var checksum = new Buffer(bytes.slice(-4));
  return getchecksum(data).then(function(realchecksum) {
    assert(bufferEqual(checksum, realchecksum), "Bad checkum");
    return data.slice(1);
  });
};

/**
 * Convert private key to a WIF.
 * @param {Buffer} privateKey - A private key to encode
 * @return {Promise.<string,undefined>} A promise that contains the
 * encoded key when fulfilled
 */
exports.encode = function(privateKey) {
  var data = Buffer.concat([new Buffer([0x80]), privateKey]);
  return getchecksum(data).then(function(checksum) {
    var bytes = Buffer.concat([data, checksum]);
    return bs58.encode(bytes);
  });
};
