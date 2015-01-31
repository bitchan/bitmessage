/**
 * Isomorphic Bitmessage crypto module. Reexports platform-dependent
 * implementations and also some common routines.
 * @module bitmessage/crypto
 */

"use strict";

var eccrypto = require("eccrypto");
var assert = require("./_util").assert;
var platform = require("./platform");

var promise = platform.promise;

/**
 * Calculate SHA-1 hash.
 * @param {Buffer} buf - Input data
 * @return {Buffer} Resulting hash.
 * @function
 * @static
 */
var sha1 = exports.sha1 = platform.sha1;

/**
 * Calculate SHA-256 hash.
 * @param {Buffer} buf - Input data
 * @return {Buffer} Resulting hash.
 * @function
 */
exports.sha256 = platform.sha256;

/**
 * Calculate SHA-512 hash.
 * @param {Buffer} buf - Input data
 * @return {Buffer} Resulting hash.
 * @function
 */
exports.sha512 = platform.sha512;

/**
 * Calculate RIPEMD-160 hash.
 * @param {Buffer} buf - Input data
 * @return {Buffer} Resulting hash.
 * @function
 */
exports.ripemd160 = platform.ripemd160;

/**
 * Generate cryptographically strong pseudo-random data.
 * @param {number} size - Number of bytes
 * @return {Buffer} Buffer with random data.
 * @function
 */
exports.randomBytes = platform.randomBytes;

/**
 * Generate new random private key.
 * @return {Buffer} New private key.
 */
exports.getPrivate = function() {
  return platform.randomBytes(32);
};

/**
 * Generate public key for the given private key.
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Buffer} A 65-byte (uncompressed) public key.
 * @function
 */
exports.getPublic = eccrypto.getPublic;

/**
 * Sign message using ecdsa-with-sha1 scheme.
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed
 * @return {Promise.<Buffer>} A promise that contains signature in DER
 * format when fulfilled.
 */
exports.sign = function(privateKey, msg) {
  var hash = sha1(msg);
  return eccrypto.sign(privateKey, hash);
};

/**
 * Verify signature using ecdsa-with-sha1 scheme.
 * @param {Buffer} publicKey - A 65-byte public key
 * @param {Buffer} msg - The message being verified
 * @param {Buffer} sig - The signature in DER format
 * @return {Promise.<undefined>} A promise that resolves on correct
 * signature and rejects on bad key or signature.
 */
exports.verify = function(publicKey, msg, sig) {
  var hash = sha1(msg);
  return eccrypto.verify(publicKey, hash, sig);
};

var SECP256K1_TYPE = 714;

// We define this structure here to avoid circular imports. However we
// rexport and document it in `structs` module for consistency.
var encrypted = exports.encrypted = {
  decode: function(buf) {
    assert(buf.length >= 118, "Buffer is too small");
    assert(buf.readUInt16BE(16, true) === SECP256K1_TYPE, "Bad curve type");
    assert(buf.readUInt16BE(18, true) === 32, "Bad Rx length");
    assert(buf.readUInt16BE(52, true) === 32, "Bad Ry length");
    var iv = new Buffer(16);
    buf.copy(iv, 0, 0, 16);
    var ephemPublicKey = new Buffer(65);
    ephemPublicKey[0] = 0x04;
    buf.copy(ephemPublicKey, 1, 20, 52);
    buf.copy(ephemPublicKey, 33, 54, 86);
    // NOTE(Kagami): We do copy instead of slice to protect against
    // possible source buffer modification by user.
    var ciphertext = new Buffer(buf.length - 118);
    buf.copy(ciphertext, 0, 86, buf.length - 32);
    var mac = new Buffer(32);
    buf.copy(mac, 0, buf.length - 32);
    return {
      iv: iv,
      ephemPublicKey: ephemPublicKey,
      ciphertext: ciphertext,
      mac: mac,
    };
  },

  encode: function(opts) {
    assert(opts.iv.length === 16, "Bad IV");
    assert(opts.ephemPublicKey.length === 65, "Bad public key");
    assert(opts.mac.length === 32, "Bad MAC");
    // 16 + 2 + 2 + 32 + 2 + 32 + ? + 32
    var buf = new Buffer(118 + opts.ciphertext.length);
    opts.iv.copy(buf);
    buf.writeUInt16BE(SECP256K1_TYPE, 16, true);  // Curve type
    buf.writeUInt16BE(32, 18, true);  // Rx length
    opts.ephemPublicKey.copy(buf, 20, 1, 33);  // Rx
    buf.writeUInt16BE(32, 52, true);  // Ry length
    opts.ephemPublicKey.copy(buf, 54, 33);  // Ry
    opts.ciphertext.copy(buf, 86);
    opts.mac.copy(buf, 86 + opts.ciphertext.length);
    return buf;
  },
};

/**
 * Encrypt message for given recepient's public key.
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} msg - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} opts - You may also
 * specify initialization vector (16 bytes) and ephemeral private key
 * (32 bytes) to get deterministic results.
 * @return {Promise.<Buffer>} - A promise that resolves with the buffer
 * in `encrypted` format successful encryption and rejects on failure.
 */
// TODO(Kagami): Properly document `opts`. Documenting multiple
// function arguments with options object at the end for now gives
// strange results (probably a bug in jsdoc).
exports.encrypt = function(publicKeyTo, msg, opts) {
  return eccrypto.encrypt(publicKeyTo, msg, opts).then(function(encObj) {
    return encrypted.encode(encObj);
  });
};

/**
 * Decrypt message using given private key.
 * @param {Buffer} privateKey - A 32-byte private key of recepient of
 * the mesage
 * @param {Buffer} buf - Encrypted data
 * @return {Promise.<Buffer>} - A promise that resolves with the
 * plaintext on successful decryption and rejects on failure.
 */
exports.decrypt = function(privateKey, buf) {
  return new promise(function(resolve) {
    var encObj = encrypted.decode(buf);
    resolve(eccrypto.decrypt(privateKey, encObj));
  });
};
