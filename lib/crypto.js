/**
 * Isomorphic Bitmessage crypto module. Reexport platform-specific
 * functions and also export some common routines.
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

exports.getPublic = eccrypto.getPublic;
