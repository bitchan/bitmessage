/**
 * Browser implementation of platform-specific routines.
 */

"use strict";

// `hash.js` is already required by
// `bitmessage -> eccrypto -> elliptic -> hash.js` so it won't add
// additional bytes to the bundle.
var hash = require("hash.js");
// Use only one submodule from `sha.js` here and in worker because it's
// faster. It will add additional bytes to the bundle but not that much
// (~9KB).
var Sha512 = require("sha.js/sha512");
var BN = require("bn.js");
var work = require("webworkify");
var assert = require("./_util").assert;

var cryptoObj = window.crypto || window.msCrypto;

exports.sha1 = function(buf) {
  return new Buffer(hash.sha1().update(buf).digest());
};

exports.sha256 = function(buf) {
  return new Buffer(hash.sha256().update(buf).digest());
};

exports.sha512 = function(buf) {
  return new Sha512().update(buf).digest();
};

exports.ripemd160 = function(buf) {
  return new Buffer(hash.ripemd160().update(buf).digest());
};

exports.randomBytes = function(size) {
  var arr = new Uint8Array(size);
  cryptoObj.getRandomValues(arr);
  return new Buffer(arr);
};

// See `platform.js` for comments.
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

var FAILBACK_POOL_SIZE = 8;

// NOTE(Kagami): We don't use promise shim in Browser implementation
// because it's supported natively in new browsers (see
// <http://caniuse.com/#feat=promises>) and we can use only new browsers
// because of the WebCryptoAPI (see
// <http://caniuse.com/#feat=cryptography>).
exports.pow = function(opts) {
  // Try to get CPU cores count otherwise fallback to default value.
  // Currenty navigator's concurrency property available in Chrome and
  // not available in Firefox; hope default value won't slow down POW
  // speed much on systems with 1 or 2 cores. There are core estimator
  // libraries exist (see <https://stackoverflow.com/q/3289465>) but
  // they are buggy. Ulimately library user could adjust pool size
  // manually.
  var poolSize = opts.poolSize || navigator.hardwareConcurrency;
  poolSize = poolSize || FAILBACK_POOL_SIZE;

  var cancel;
  var powp = new Promise(function(resolve, reject) {
    assert(typeof poolSize === "number", "Bad pool size");
    assert(poolSize >= 1, "Pool size is too low");
    assert(poolSize <= 1024, "Pool size is too high");
    assert(typeof opts.target === "number", "Bad target");
    assert(opts.target >= 0, "Target is too low");
    assert(opts.target <= 9007199254740991, "Target is too high");
    assert(Buffer.isBuffer(opts.initialHash), "Bad initial hash");
    assert(opts.initialHash.length === 64, "Bad initial hash");

    function terminateAll() {
      while (workers.length) {
        workers.shift().terminate();
      }
    }

    function onmessage(e) {
      terminateAll();
      if (e.data >= 0) {
        resolve(e.data);
      } else {
        // It's very unlikely that execution will ever reach this place.
        // Currently the only reason why Worker may return value less
        // than zero is a 32-bit nonce overflow (see worker
        // implementation). It's 4G double hashes.
        reject(new Error("uint32_t nonce overflow"));
      }
    }

    function onerror(e) {
      // XXX(Kagami): `onerror` events fires in Chrome even after all
      // workers were terminated. It doesn't cause wrong behaviour but
      // beware that this function may be executed several times.
      terminateAll();
      reject(e);
    }

    var workers = [];
    var worker;
    for (var i = 0; i < poolSize; i++) {
      worker = work(require("./worker.browser.js"));
      workers.push(worker);
      // NOTE(Kagami): There is no race condition here. `onmessage` can
      // only be called _after_ this for-loop finishes. See
      // <https://stackoverflow.com/a/18192122> for details.
      worker.onmessage = onmessage;
      worker.onerror = onerror;
      worker.postMessage({
        num: i,
        poolSize: poolSize,
        target: opts.target,
        initialHash: opts.initialHash,
      });
    }

    cancel = function(e) {
      terminateAll();
      reject(e);
    };
  });
  // Allow to stop a POW via custom function added to the Promise
  // instance.
  powp.cancel = cancel;
  return powp;
};

exports.promise = window.Promise;
