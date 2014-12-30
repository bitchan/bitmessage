/**
 * Node.js Bitmessage crypto implementation.
 * @module bitmessage/crypto-platform
 */

"use strict";

require("es6-promise").polyfill();
var crypto = require("crypto");

/**
 * Calculate SHA-512 hash.
 * @param {Buffer} buf - Input data
 * @return {Promise.<Buffer>} Resulting hash.
 */
exports.sha512 = function(buf) {
  var hash = crypto.createHash("sha512");
  hash.update(buf);
  return Promise.resolve(hash.digest());
};

/**
 * Calculate SHA-256 hash.
 * @param {Buffer} buf - Input data
 * @return {Promise.<Buffer>} Resulting hash.
 */
exports.sha256 = function(buf) {
  var hash = crypto.createHash("sha256");
  hash.update(buf);
  return Promise.resolve(hash.digest());
};

/**
 * Calculate RIPEMD-160 hash.
 * @param {Buffer} buf - Input data
 * @return {Promise.<Buffer>} Resulting hash.
 */
exports.ripemd160 = function(buf) {
  var hash = crypto.createHash("ripemd160");
  hash.update(buf);
  return Promise.resolve(hash.digest());
};

/**
 * Generate cryptographically strong pseudo-random data.
 * @param {number} size - Number of bytes
 * @return {Buffer} Buffer with random data.
 */
exports.randomBytes = function(size) {
  return crypto.randomBytes(size);
};
