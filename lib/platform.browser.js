/**
 * Browser implementation of platform-specific routines.
 */

"use strict";

var hash = require("hash.js");
var BN = require("bn.js");
var assert = require("./util").assert;

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

var B64 = new BN("18446744073709551616");

exports.getTarget = function(opts) {
  var length = new BN(opts.payloadLength);
  length.iaddn(8);
  length.iaddn(opts.payloadLengthExtraBytes);
  var denominator = new BN(opts.ttl);
  denominator.imul(length);
  denominator.idivn(65536);
  denominator.iadd(length);
  denominator.imul(new BN(opts.nonceTrialsPerByte));
  var target = parseInt(B64.div(denominator).toString(16), 16);
  assert(target <= 9007199254740991, "Unsafe target");
  return target;
};
