/**
 * Implements proof of work.
 * @see {@link https://bitmessage.org/wiki/Proof_of_work}
 * @module bitmessage/pow
 */

"use strict";

var bmcrypto = require("./crypto");
var platform = require("./platform");

var DEFAULT_TRIALS_PER_BYTE = 1000;
var DEFAULT_EXTRA_BYTES = 1000;

/**
 * Calculate target
 * @param {Object} opts - Target options
 * @return {number} Target.
 */
// TODO(Kagami): Find a way how to document object params properly.
// Just a wrapper around platform-specific implementation.
exports.getTarget = function(opts) {
  var payloadLength = opts.payloadLength || opts.payload.length;
  var nonceTrialsPerByte = opts.nonceTrialsPerByte;
  // Automatically raise lower values per spec.
  if (!nonceTrialsPerByte || nonceTrialsPerByte < DEFAULT_TRIALS_PER_BYTE) {
    nonceTrialsPerByte = DEFAULT_TRIALS_PER_BYTE;
  }
  var payloadLengthExtraBytes = opts.payloadLengthExtraBytes;
  if (!payloadLengthExtraBytes || payloadLengthExtraBytes < DEFAULT_EXTRA_BYTES) {
    payloadLengthExtraBytes = DEFAULT_EXTRA_BYTES;
  }
  return platform.getTarget({
    ttl: opts.ttl,
    payloadLength: payloadLength,
    nonceTrialsPerByte: nonceTrialsPerByte,
    payloadLengthExtraBytes: payloadLengthExtraBytes,
  });
};

/**
 * Check a POW.
 * @param {Object} opts - Proof of work options
 * @return {boolean} Is the proof of work sufficient.
 */
exports.check = function(opts) {
  var initialHash;
  var nonce;
  if (opts.data) {
    nonce = opts.data.slice(0, 8);
    initialHash = bmcrypto.sha512(opts.data.slice(8));
  } else {
    if (typeof opts.nonce === "number") {
      nonce = new Buffer(8);
      // High 32 bits.
      nonce.writeUInt32BE(Math.floor(opts.nonce / 4294967296), 0, true);
      // Low 32 bits.
      nonce.writeUInt32BE(opts.nonce % 4294967296, 4, true);
    } else {
      nonce = opts.nonce;
    }
    initialHash = opts.initialHash;
  }
  var targetHi = Math.floor(opts.target / 4294967296);
  var targetLo = opts.target % 4294967296;
  var dataToHash = Buffer.concat([nonce, initialHash]);
  var resultHash = bmcrypto.sha512(bmcrypto.sha512(dataToHash));
  var trialHi = resultHash.readUInt32BE(0, true);
  if (trialHi > targetHi) {
    return false;
  } else if (trialHi < targetHi) {
    return true;
  } else {
    var trialLo = resultHash.readUInt32BE(4, true);
    return trialLo <= targetLo;
  }
};
