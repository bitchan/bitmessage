/**
 * Implements proof of work.
 * @see {@link https://bitmessage.org/wiki/Proof_of_work}
 * @module bitmessage/pow
 */
// TODO(Kagami): Find a way how to document object params properly.

"use strict";

var objectAssign = Object.assign || require("object-assign");
var bmcrypto = require("./crypto");
var platform = require("./platform");
var util = require("./_util");

/**
 * Calculate target.
 * @param {Object} opts - Target options
 * @return {number} Target.
 * @function
 * @static
 */
// Just a wrapper around platform-specific implementation.
var getTarget = exports.getTarget = function(opts) {
  var payloadLength = opts.payloadLength || opts.payload.length;
  return platform.getTarget({
    ttl: opts.ttl,
    payloadLength: payloadLength,
    nonceTrialsPerByte: util.getTrials(opts),
    payloadLengthExtraBytes: util.getExtraBytes(opts),
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
  var target = opts.target;
  if (target === undefined) {
    target = getTarget(opts);
  }
  if (opts.payload) {
    nonce = opts.payload.slice(0, 8);
    initialHash = bmcrypto.sha512(opts.payload.slice(8));
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
  var targetHi = Math.floor(target / 4294967296);
  var targetLo = target % 4294967296;
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

/**
 * Do a POW.
 * @param {Object} opts - Proof of work options
 * @param {?Buffer} opts.data - Object message payload without nonce to
 * get the initial hash from
 * @param {?Buffer} opts.initialHash - Or already computed initial hash
 * @param {number} opts.target - POW target
 * @return {Promise.<number>} A promise that contains computed nonce for
 * the given target when fulfilled.
 */
exports.doAsync = function(opts) {
  var initialHash;
  if (opts.data) {
    initialHash = bmcrypto.sha512(opts.data);
  } else {
    initialHash = opts.initialHash;
  }
  opts = objectAssign({}, opts, {initialHash: initialHash});
  return platform.pow(opts);
};
