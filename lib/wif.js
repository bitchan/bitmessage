/**
 * Implements WIF encoding/decoding.
 * @see {@link https://en.bitcoin.it/wiki/Wallet_import_format}
 * @module bitmessage/wif
 */

"use strict";

var bufferEqual = require("buffer-equal");
var bs58 = require("bs58");
var assert = require("./_util").assert;
var bmcrypto = require("./crypto");

// Compute the WIF checksum for the given data.
function getwifchecksum(data) {
  return bmcrypto.sha256(bmcrypto.sha256(data)).slice(0, 4);
}

/**
 * Decode WIF encoded private key.
 * @param {string} wif - Encoded key
 * @return {Buffer} Private key.
 */
exports.decode = function(wif) {
  var bytes = bs58.decode(wif);
  assert(bytes[0] === 0x80, "Bad WIF");
  var data = new Buffer(bytes.slice(0, -4));
  var checksum = new Buffer(bytes.slice(-4));
  assert(bufferEqual(checksum, getwifchecksum(data)), "Bad checkum");
  return data.slice(1);
};

/**
 * Convert private key to a WIF.
 * @param {Buffer} privateKey - A private key to encode
 * @return {string} Encoded private key.
 */
exports.encode = function(privateKey) {
  var data = Buffer.concat([new Buffer([0x80]), privateKey]);
  var checksum = getwifchecksum(data);
  var bytes = Buffer.concat([data, checksum]);
  return bs58.encode(bytes);
};
