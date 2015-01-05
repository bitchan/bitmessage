/**
 * Browser implementation of platform-specific routines.
 */

"use strict";

var createHash = require("sha.js");
var hash = require("hash.js");

exports.sha512 = function(buf) {
  return createHash("sha512").update(buf).digest();
};

exports.sha256 = function(buf) {
  return hash.sha256().update(buf).digest();
};

exports.ripemd160 = function(buf) {
  return hash.ripemd160().update(buf).digest();
};

exports.randomBytes = function(size) {
  var arr = new Uint8Array(size);
  window.crypto.getRandomValues(arr);
  return new Buffer(arr);
};
