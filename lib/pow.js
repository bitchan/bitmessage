/**
 * Implements proof of work.
 * @see {@link https://bitmessage.org/wiki/Proof_of_work}
 * @module bitmessage/pow
 */

"use strict";

var platform = require("./platform");

var DEFAULT_TRIALS_PER_BYTE = 1000;
var DEFAULT_EXTRA_BYTES = 1000;

/**
 * Calculate target
 * @param {{ttl: number, payloadLength: number}} opts - Target options
 * @return {number} Target.
 */
// Just a wrapper around platform-specific implementation.
exports.getTarget = function(opts) {
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
    payloadLength: opts.payloadLength,
    nonceTrialsPerByte: nonceTrialsPerByte,
    payloadLengthExtraBytes: payloadLengthExtraBytes,
  });
};
