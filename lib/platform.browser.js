/**
 * Browser implementation of platform-specific routines.
 */

"use strict";

var hash = require("hash.js");

exports.sha512 = function(buf) {
  return new Buffer(hash.sha512().update(buf).digest());
};

exports.sha256 = function(buf) {
  return new Buffer(hash.sha256().update(buf).digest());
};

exports.ripemd160 = function(buf) {
  return new Buffer(hash.ripemd160().update(buf).digest());
};

exports.randomBytes = function(size) {
  var arr = new Uint8Array(size);
  window.crypto.getRandomValues(arr);
  return new Buffer(arr);
};
