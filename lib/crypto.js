/**
 * Isomorphic Bitmessage crypto module. Reexports platform-dependent
 * implementations and and also some common routines.
 * @module bitmessage/crypto
 */

"use strict";

var eccrypto = require("eccrypto");
var platform = require("./platform");

/**
 * Calculate SHA-512 hash.
 * @param {Buffer} buf - Input data
 * @return {Buffer} Resulting hash.
 * @function
 */
exports.sha512 = platform.sha512;

/**
 * Calculate SHA-256 hash.
 * @param {Buffer} buf - Input data
 * @return {Buffer} Resulting hash.
 * @function
 */
exports.sha256 = platform.sha256;

/**
 * Calculate RIPEMD-160 hash.
 * @param {Buffer} buf - Input data
 * @return {Buffer} Resulting hash.
 * @function
 */
exports.ripemd160 = platform.ripemd160;

/**
 * Generate cryptographically strong pseudo-random data.
 * @param {number} size - Number of bytes
 * @return {Buffer} Buffer with random data.
 * @function
 */
exports.randomBytes = platform.randomBytes;

/**
 * Generate new random private key.
 * @return {Buffer} New private key.
 */
exports.getPrivate = function() {
  return platform.randomBytes(32);
};

/**
 * Generate public key for a given private key.
 * @param {Buffer} privateKey - Private key
 * @return {Buffer} Public key.
 * @function
 */
exports.getPublic = eccrypto.getPublic;
