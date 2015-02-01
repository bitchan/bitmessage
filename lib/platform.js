/**
 * Node.js implementation of platform-specific routines.
 */

"use strict";

var os = require("os");
var crypto = require("crypto");
var PPromise = typeof Promise === "undefined" ?
               require("es6-promise").Promise :
               Promise;
var bignum = require("bignum");
var assert = require("./_util").assert;
var worker = require("./worker");

var createHash = crypto.createHash;

exports.sha1 = function(buf) {
  return createHash("sha1").update(buf).digest();
};

exports.sha256 = function(buf) {
  return createHash("sha256").update(buf).digest();
};

exports.sha512 = function(buf) {
  return createHash("sha512").update(buf).digest();
};

exports.ripemd160 = function(buf) {
  return createHash("ripemd160").update(buf).digest();
};

exports.randomBytes = crypto.randomBytes;

// 2^80.
var B80 = bignum("1208925819614629174706176");

// NOTE(Kagami): We can't calculate entire target in JavaScript but the
// result can be represented in native number type without losing
// precision (targets mainly much less than 2^53).
exports.getTarget = function(opts) {
  // Slightly rearrange calculations and compute it bottom-up,
  // right-to-left. See also:
  // <https://github.com/Bitmessage/PyBitmessage/issues/758>.
  var length = bignum(opts.payloadLength).add(opts.payloadLengthExtraBytes);
  var denominator = bignum(opts.ttl)
    .add(65536)
    .mul(length)
    .mul(opts.nonceTrialsPerByte);
  var target = B80.div(denominator).toNumber();
  assert(target <= 9007199254740991, "Unsafe target");
  return target;
};

exports.pow = function(opts) {
  // TODO(Kagami): Allow to cancel a POW (see `platform.browser.js`).
  return new PPromise(function(resolve, reject) {
    var poolSize = opts.poolSize || os.cpus().length;
    worker.powAsync(
      poolSize,
      opts.target,
      opts.initialHash,
      function(err, nonce) {
        if (err) {
          reject(err);
        } else {
          resolve(nonce);
        }
      }
    );
  });
};

exports.Promise = PPromise;
