/**
 * Web Worker routines for Browser platform.
 */

"use strict";

// NOTE(Kagami): In order to use it you need to create separate
// browserify bundle for this file, place it somewhere in your HTTP
// server assets path (under the same origin with your application code)
// and then pass appropriate `workerUrl` value to the function that
// spawns workers.
// You may also try to pass object URL instead. See
// <http://mdn.io/worker.worker>, <https://stackoverflow.com/q/10343913>
// for details.

// XXX(Kagami): This is rather unpleasent that we use different SHA-2
// implementations for main library code and for worker code (we use
// `sha.js` here because it's faster). Though worker code lays in
// separate file so it shouldn't result in any download overhead.
var createHash = require("sha.js");

function sha512(buf) {
  return createHash("sha512").update(buf).digest();
}

function pow(opts) {
  var nonce = opts.num;
  var poolSize = opts.poolSize;
  var message = new Buffer(72);
  message.fill(0);
  Buffer(opts.initialHash).copy(message, 8);
  var targetHi = Math.floor(opts.target / 4294967296);
  var targetLo = opts.target % 4294967296;
  var digest, trialHi, trialLo;

  while (true) {
    // uint32_t overflow. There is no much need to fix it since 4G
    // double hashes would we computed too long anyway in a Browser.
    if (nonce > 4294967295) {
      return -1;
    }

    message.writeUInt32BE(nonce, 4, true);
    digest = sha512(sha512(message));
    trialHi = digest.readUInt32BE(0, true);

    if (trialHi > targetHi) {
      nonce += poolSize;
    } else if (trialHi === targetHi) {
      trialLo = digest.readUInt32BE(4, true);
      if (trialLo > targetLo) {
        nonce += poolSize;
      } else {
        return nonce;
      }
    } else {
      return nonce;
    }
  }
}

onmessage = function(e) {  // jshint ignore:line
  var nonce = pow(e.data);
  postMessage(nonce);  // jshint ignore:line
};
