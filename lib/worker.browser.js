/**
 * Web Worker routines for Browser platform.
 */

"use strict";

var Sha512 = require("sha.js/sha512");

function sha512(buf) {
  return new Sha512().update(buf).digest();
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

module.exports = function(self) {
  self.onmessage = function(e) {
    self.postMessage(pow(e.data));
  };
};
