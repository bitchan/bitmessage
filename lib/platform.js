/**
 * Node.js implementation of platform-specific routines.
 */

"use strict";

var crypto = require("crypto");
var bignum = require("bignum");
var assert = require("./util").assert;

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

// 2^64.
var B64 = bignum("18446744073709551616");

// NOTE(Kagami): We can't calculate entire target in JavaScript but the
// result can be represented in native number type without losing
// precision (targets mainly much less than 2^53).
exports.getTarget = function(opts) {
  // Calculate it bottom-up, right-to-left.
  var length = bignum(opts.payloadLength)
    // To account for the nonce which we will append later.
    .add(8)
    .add(opts.payloadLengthExtraBytes);
  var denominator = bignum(opts.ttl)
    .mul(length)
    .div(65536)
    .add(length)
    .mul(opts.nonceTrialsPerByte);
  var target = B64.div(denominator).toNumber();
  assert(target <= 9007199254740991, "Unsafe target");
  return target;
};
