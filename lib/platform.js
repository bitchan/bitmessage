/**
 * Node.js implementation of platform-specific routines.
 */

"use strict";

var crypto = require("crypto");
var createHash = crypto.createHash;

exports.sha512 = function(buf) {
  return createHash("sha512").update(buf).digest();
};

exports.sha256 = function(buf) {
  return createHash("sha256").update(buf).digest();
};

exports.ripemd160 = function(buf) {
  return createHash("ripemd160").update(buf).digest();
};

exports.randomBytes = crypto.randomBytes;
