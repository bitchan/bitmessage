/**
 * Working with objects.
 * NOTE: All operations with objects in this module are asynchronous and
 * return promises.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Object_types}
 * @module bitmessage/objects
 */
// TODO(Kagami): Document object-like params.
// FIXME(Kagami): Think through API, we may want to get decoded
// structure even if it contains unsupported version. Also error
// handling may need some refactoring.

"use strict";

var objectAssign = Object.assign || require("object-assign");
var assert = require("./_util").assert;
var promise = require("./platform").promise;
var bmcrypto = require("./crypto");
var Address = require("./address");
var var_int = require("./structs").var_int;
var PubkeyBitfield = require("./structs").PubkeyBitfield;
var object = require("./structs").object;
var util = require("./_util");

/**
 * `getpubkey` object. When a node has the hash of a public key (from an
 * address) but not the public key itself, it must send out a request
 * for the public key.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#getpubkey}
 * @namespace
 */
exports.getpubkey = {
  /**
   * Decode `getpubkey` object message payload.
   * @param {Buffer} buf - Message payload
   * @return {Promise.<Object>} A promise that contains decoded
   * `getpubkey` object structure when fulfilled.
   */
  decodeAsync: function(buf) {
    return new promise(function(resolve) {
      var decoded = object.decode(buf);
      assert(decoded.type === object.GETPUBKEY, "Wrong object type");
      assert(decoded.version >= 2, "getpubkey version is too low");
      assert(decoded.version <= 4, "getpubkey version is too high");
      var payload = decoded.payload;
      delete decoded.payload;
      if (decoded.version < 4) {
        assert(payload.length === 20, "getpubkey ripe is too small");
        // Payload is copied so it's safe to return it right away.
        decoded.ripe = payload;
      } else {
        assert(payload.length === 32, "getpubkey tag is too small");
        // Payload is copied so it's safe to return it right away.
        decoded.tag = payload;
      }
      resolve(decoded);
    });
  },

  /**
   * Encode `getpubkey` object message payload.
   * @param {Object} opts - `getpubkey` object options
   * @return {Promise.<Buffer>} A promise that contains encoded message
   * payload when fulfilled.
   */
  // FIXME(Kagami): Do a POW.
  encodeAsync: function(opts) {
    return new promise(function(resolve) {
      opts = objectAssign({}, opts);
      opts.type = object.GETPUBKEY;
      // Bitmessage address of recepeint of `getpubkey` message.
      var to = Address.decode(opts.to);
      assert(to.version >= 2, "Address version is too low");
      assert(to.version <= 4, "Address version is too high");
      opts.version = to.version;
      opts.stream = to.stream;
      opts.payload = to.version < 4 ? to.getRipe() : to.getTag();
      // POW calculation here.
      var nonce = new Buffer(8);
      opts.nonce = nonce;
      resolve(object.encode(opts));
    });
  },
};

// Helper function for `pubkey.decode`.
function extractPubkeyV2(payload) {
  var decoded = {};
  // Payload is copied so it's safe to return it right away.
  decoded.behavior = PubkeyBitfield(payload.slice(0, 4));
  var signPublicKey = decoded.signPublicKey = new Buffer(65);
  signPublicKey[0] = 4;
  payload.copy(signPublicKey, 1, 4, 68);
  var encPublicKey = decoded.encPublicKey = new Buffer(65);
  encPublicKey[0] = 4;
  payload.copy(encPublicKey, 1, 68, 132);
  return decoded;
}

// Helper function for `pubkey.decode`.
function extractPubkeyV3(payload) {
  var decoded = {};
  var length = 0;
  var decodedTrials = var_int.decode(payload);
  decoded.nonceTrialsPerByte = decodedTrials.value;
  length += decodedTrials.length;
  var decodedExtraBytes = var_int.decode(decodedTrials.rest);
  decoded.payloadLengthExtraBytes = decodedExtraBytes.value;
  length += decodedExtraBytes.length;
  var decodedSigLength = var_int.decode(decodedExtraBytes.rest);
  decoded.signature = decodedSigLength.rest.slice(0, decodedSigLength.value);
  var siglen = decodedSigLength.length + decodedSigLength.value;
  length += siglen;
  // Internal value.
  decoded._siglen = siglen;
  decoded.length = length;
  return decoded;
}

/**
 * `pubkey` object.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#pubkey}
 * @namespace
 */
exports.pubkey = {
  /**
   * Decode `pubkey` object message payload.
   * @param {Buffer} buf - Message payload
   * @param {?Object} opts - Decoding options
   * @return {Promise.<Object>} A promise that contains decoded `pubkey`
   * object structure when fulfilled.
   */
  decodeAsync: function(buf, opts) {
    return new promise(function(resolve, reject) {
      opts = opts || {};
      var neededPubkeys = opts.neededPubkeys || {};
      var decoded = object.decode(buf);
      assert(decoded.type === object.PUBKEY, "Wrong object type");
      var payload = decoded.payload;
      delete decoded.payload;
      var version = decoded.version;
      assert(version >= 2, "Address version is too low");
      assert(version <= 4, "Address version is too high");
      var siglen, sig, dataToVerify, pubkeyp;
      var addr, addrs, tag, pubkeyEncPrivateKey, dataToDecrypt;
      var length = 132;

      // v2 pubkey.
      if (version === 2) {
        // 4 + 64 + 64
        assert(payload.length === 132, "Bad pubkey v2 object payload length");
        objectAssign(decoded, extractPubkeyV2(payload));
        // Real data length.
        decoded.length = length;
        return resolve(decoded);
      }

      // v3 pubkey.
      if (version === 3) {
        // 4 + 64 + 64 + (1+) + (1+) + (1+)
        assert(payload.length >= 135, "Bad pubkey v3 object payload length");
        objectAssign(decoded, extractPubkeyV2(payload));
        objectAssign(decoded, extractPubkeyV3(payload.slice(132)));
        siglen = util.popkey(decoded, "_siglen");
        length += decoded.length;
        // Real data length.
        decoded.length = length;
        // Object message payload without nonce up to sigLength.
        dataToVerify = buf.slice(8, decoded.headerLength + length - siglen);
        sig = decoded.signature;
        pubkeyp = bmcrypto.verify(decoded.signPublicKey, dataToVerify, sig)
          .then(function() {
            return decoded;
          });
        return resolve(pubkeyp);
      }

      // v4 pubkey.

      // `neededPubkeys` is either single address or addresses array or
      // Object key-by-tag. Time to match the tag is O(1), O(n), O(1)
      // respectfully.
      if (Address.isAddress(neededPubkeys)) {
        addr = neededPubkeys;
        neededPubkeys = {};
        neededPubkeys[addr.getTag()] = addr.getPubkeyPrivateKey();
      } else if (Array.isArray(neededPubkeys)) {
        addrs = neededPubkeys;
        neededPubkeys = {};
        addrs.forEach(function(a) {
          neededPubkeys[a.getTag()] = a.getPubkeyPrivateKey();
        });
      }

      assert(payload.length >= 32, "Bad pubkey v4 object payload length");
      tag = decoded.tag = payload.slice(0, 32);
      pubkeyEncPrivateKey = neededPubkeys[tag];
      if (!pubkeyEncPrivateKey) {
        return reject(new Error("You are not interested in this pubkey v4"));
      }
      dataToDecrypt = payload.slice(32);
      pubkeyp = bmcrypto.decrypt(pubkeyEncPrivateKey, dataToDecrypt)
        .then(function(decrypted) {
          // 4 + 64 + 64 + (1+) + (1+) + (1+)
          assert(
            decrypted.length >= 135,
            "Bad pubkey v4 object payload length");
          objectAssign(decoded, extractPubkeyV2(decrypted));
          objectAssign(decoded, extractPubkeyV3(decrypted.slice(132)));
          siglen = util.popkey(decoded, "_siglen");
          length += decoded.length;
          // Real data length.
          // Since data is encrypted, entire payload is used.
          decoded.length = payload.length;
          dataToVerify = Buffer.concat([
            // Object header without nonce + tag.
            buf.slice(8, decoded.headerLength + 32),
            // Unencrypted pubkey data without signature.
            decrypted.slice(0, length - siglen),
          ]);
          sig = decoded.signature;
          return bmcrypto.verify(decoded.signPublicKey, dataToVerify, sig);
        }).then(function() {
          return decoded;
        });
      resolve(pubkeyp);
    });
  },

  /**
   * Encode `pubkey` object message payload.
   * @param {Object} opts - `pubkey` object options
   * @return {Promise.<Buffer>} A promise that contains encoded message
   * payload when fulfilled.
   */
  // FIXME(Kagami): Do a POW.
  encodeAsync: function(opts) {
    return new promise(function(resolve) {
      opts = objectAssign({}, opts);
      opts.type = object.PUBKEY;
      // Originator of `pubkey` message.
      var from = Address.decode(opts.from);
      var nonceTrialsPerByte = util.getTrials(from);
      var payloadLengthExtraBytes = util.getExtraBytes(from);
      // Bitmessage address of recepient of `pubkey` message.
      var to, version, stream;
      if (opts.to) {
        to = Address.decode(opts.to);
        version = to.version;
        stream = to.stream;
      } else {
        version = opts.version || 4;
        stream = opts.stream || 1;
      }
      assert(version >= 2, "Address version is too low");
      assert(version <= 4, "Address version is too high");
      opts.version = version;
      opts.stream = stream;
      var obj, pubkeyp;

      // v2 pubkey.
      if (version === 2) {
        opts.payload = Buffer.concat([
          from.behavior.buffer,
          from.signPublicKey.slice(1),
          from.encPublicKey.slice(1),
        ]);
        obj = object.encodeWithoutNonce(opts);
        // POW calculation here.
        var nonce = new Buffer(8);
        obj = Buffer.concat([nonce, obj]);
        return resolve(obj);
      }

      var pubkeyData = [
        from.behavior.buffer,
        from.signPublicKey.slice(1),
        from.encPublicKey.slice(1),
        var_int.encode(nonceTrialsPerByte),
        var_int.encode(payloadLengthExtraBytes),
      ];

      // v3 pubkey.
      if (version === 3) {
        opts.payload = Buffer.concat(pubkeyData);
        obj = object.encodeWithoutNonce(opts);
        pubkeyp = bmcrypto
          .sign(from.signPrivateKey, obj)
          .then(function(sig) {
            // POW calculation here.
            var nonce = new Buffer(8);
            // Append signature to the encoded object and we are done.
            return Buffer.concat([
              nonce,
              obj,
              var_int.encode(sig.length),
              sig,
            ]);
          });
        return resolve(pubkeyp);
      }

      // v4 pubkey.
      opts.payload = from.getTag();
      obj = object.encodeWithoutNonce(opts);
      var dataToSign = Buffer.concat([obj].concat(pubkeyData));
      var pubkeyEncPrivateKey = from.getPubkeyPrivateKey();
      var pubkeyEncPublicKey = bmcrypto.getPublic(pubkeyEncPrivateKey);
      pubkeyp = bmcrypto
        .sign(from.signPrivateKey, dataToSign)
        .then(function(sig) {
          var dataToEnc = pubkeyData.concat(var_int.encode(sig.length), sig);
          dataToEnc = Buffer.concat(dataToEnc);
          return bmcrypto.encrypt(pubkeyEncPublicKey, dataToEnc);
        }).then(function(enc) {
          // POW calculation here.
          var nonce = new Buffer(8);
          // Concat object header with ecnrypted data and we are done.
          return Buffer.concat([nonce, obj, enc]);
        });
      resolve(pubkeyp);
    });
  },
};
