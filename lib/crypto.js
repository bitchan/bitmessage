/**
 * Isomorphic Bitmessage crypto module. Reexports
 * [platform-specific functions]{@link module:bitmessage/crypto-platform}
 * and also some common routines.
 * @module bitmessage/crypto
 */

"use strict";

var eccrypto = require("eccrypto");
var cryptoPlatform = require("./crypto-platform");

Object.keys(cryptoPlatform).forEach(function(key) {
  exports[key] = cryptoPlatform[key];
});

/**
 * Generate new random private key.
 * @return {Buffer} New private key.
 */
exports.getPrivate = function() {
  return cryptoPlatform.randomBytes(32);
};

/**
 * Generate public key for a given private key.
 * @param {Buffer} privateKey - Private key
 * @return {Buffer} Public key.
 * @function
 */
exports.getPublic = eccrypto.getPublic;
