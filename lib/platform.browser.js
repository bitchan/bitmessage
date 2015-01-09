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

var FAILBACK_POOL_SIZE = 8;

// NOTE(Kagami): We don't use promise shim in Browser implementation
// because it's supported natively in new browsers (see
// <http://caniuse.com/#feat=promises>) and we can use only new browsers
// because of the WebCryptoAPI (see
// <http://caniuse.com/#feat=cryptography>).
exports.doPOW = function(opts) {
  // Try to get native cores count then fallback to more or less
  // reasonable value. See <https://stackoverflow.com/q/3289465> for
  // details.
  var poolSize = opts.poolSize || navigator.hardwareConcurrency;
  poolSize = poolSize || FAILBACK_POOL_SIZE;

  // Check all input params prematurely to not let promise executor or
  // worker to fail because of it.
  assert(poolSize > 0, "Bad pool size");
  assert(opts.workerUrl, "Bad worker URL");
  assert(typeof opts.target === "number", "Bad target");
  assert(Buffer.isBuffer(opts.initialHash), "Bad initial hash");

  var cancel;
  var promise = new Promise(function(resolve, reject) {
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
        // implementation). It's more than 4G double hashes.
        reject();
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
      worker = new Worker(opts.workerUrl);
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
  // Allow to stop POW via custom function added to the Promise
  // instance.
  promise.cancel = cancel;
  return promise;
};
