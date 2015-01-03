/**
 * Browser implementation of platform-specific routines.
 */

"use strict";

var createHash = require("sha.js");
var ripemd160 = require("ripemd160");

exports.sha512 = function(buf) {
  return createHash("sha512").update(buf).digest();
};

exports.sha256 = function(buf) {
  return createHash("sha256").update(buf).digest();
};

exports.ripemd160 = ripemd160;

exports.randomBytes = function(size) {
  var arr = new Uint8Array(size);
  window.crypto.getRandomValues(arr);
  return new Buffer(arr);
};
