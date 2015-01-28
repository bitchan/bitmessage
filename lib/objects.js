/**
 * Working with objects.
 * NOTE: Most operations with objects in this module are asynchronous
 * and return promises.
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
var structs = require("./structs");
var util = require("./_util");

var var_int = structs.var_int;
var PubkeyBitfield = structs.PubkeyBitfield;
var message = structs.message;
var object = structs.object;

/**
 * Try to get type of the given encoded object message.
 * Note that this function doesn't do any validation because it is
 * already provided by `object.decode` routine. Normally you call this
 * for each incoming object message and then call decode function of the
 * appropriate object handler.
 * @param {Buffer} buf - Buffer that starts with encoded object message
 * @return {?integer} Object's type if any
 */
exports.getType = function(buf) {
  // Message header: 4 + 12 + 4 + 4
  // Object header: 8 + 8 + 4
  if (buf.length < 44) {
    return;
  }
  return buf.readUInt32BE(40, true);
};

/**
 * Try to get type of the given object message payoad.
 * Note that this function doesn't do any validation because it is
 * already provided by `object.decodePayload` routine. Normally you call
 * this for each incoming object message and then call decode function
 * of the appropriate object handler.
 * @param {Buffer} buf - Buffer that starts with object message payload
 * @return {?integer} Object's type if any
 */
exports.getPayloadType = function(buf) {
  // Object header: 8 + 8 + 4
  if (buf.length < 20) {
    return;
  }
  return buf.readUInt32BE(16, true);
};

/**
 * `getpubkey` object. When a node has the hash of a public key (from an
 * address) but not the public key itself, it must send out a request
 * for the public key.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#getpubkey}
 * @namespace
 * @static
 */
var getpubkey = exports.getpubkey = {
  /**
   * Decode `getpubkey` object message.
   * @param {Buffer} buf - Message
   * @return {Promise.<Object>} A promise that contains decoded
   * `getpubkey` object structure when fulfilled.
   */
  decodeAsync: function(buf) {
    return new promise(function(resolve) {
      var decoded = message.decode(buf);
      assert(decoded.command === "object", "Bad command");
      resolve(getpubkey.decodePayloadAsync(decoded.payload));
    });
  },

  /**
   * Decode `getpubkey` object message payload.
   * @param {Buffer} buf - Message payload
   * @return {Promise.<Object>} A promise that contains decoded
   * `getpubkey` object structure when fulfilled.
   */
  decodePayloadAsync: function(buf) {
    return new promise(function(resolve) {
      var decoded = object.decodePayload(buf);
      assert(decoded.type === object.GETPUBKEY, "Wrong object type");
      assert(decoded.version >= 2, "getpubkey version is too low");
      assert(decoded.version <= 4, "getpubkey version is too high");
      var objectPayload = decoded.objectPayload;
      delete decoded.objectPayload;
      if (decoded.version < 4) {
        assert(objectPayload.length === 20, "getpubkey ripe is too small");
        // Object payload is copied so it's safe to return it right away.
        decoded.ripe = objectPayload;
      } else {
        assert(objectPayload.length === 32, "getpubkey tag is too small");
        // Object payload is copied so it's safe to return it right away.
        decoded.tag = objectPayload;
      }
      resolve(decoded);
    });
  },

  /**
   * Encode `getpubkey` object message.
   * @param {Object} opts - `getpubkey` object options
   * @return {Promise.<Buffer>} A promise that contains encoded message
   * when fulfilled.
   */
  encodeAsync: function(opts) {
    return getpubkey.encodePayloadAsync(opts).then(function(payload) {
      return message.encode("object", payload);
    });
  },

  /**
   * Encode `getpubkey` object message payload.
   * @param {Object} opts - `getpubkey` object options
   * @return {Promise.<Buffer>} A promise that contains encoded message
   * payload when fulfilled.
   */
  // FIXME(Kagami): Do a POW.
  encodePayloadAsync: function(opts) {
    return new promise(function(resolve) {
      opts = objectAssign({}, opts);
      opts.type = object.GETPUBKEY;
      // Bitmessage address of recepeint of `getpubkey` message.
      var to = Address.decode(opts.to);
      assert(to.version >= 2, "Address version is too low");
      assert(to.version <= 4, "Address version is too high");
      opts.version = to.version;
      opts.stream = to.stream;
      opts.objectPayload = to.version < 4 ? to.ripe : to.getTag();
      // POW calculation here.
      var nonce = new Buffer(8);
      opts.nonce = nonce;
      resolve(object.encodePayload(opts));
    });
  },
};

// Helper function for `pubkey.decode`.
// Extract pubkey data from decrypted object payload.
function extractPubkeyV2(buf) {
  var decoded = {};
  // Object payload is copied so it's safe to return it right away.
  decoded.behavior = PubkeyBitfield(buf.slice(0, 4));
  var signPublicKey = decoded.signPublicKey = new Buffer(65);
  signPublicKey[0] = 4;
  buf.copy(signPublicKey, 1, 4, 68);
  var encPublicKey = decoded.encPublicKey = new Buffer(65);
  encPublicKey[0] = 4;
  buf.copy(encPublicKey, 1, 68, 132);
  return decoded;
}

// Helper function for `pubkey.decode`.
// Extract pubkey data from decrypted object payload.
function extractPubkeyV3(buf) {
  var decoded = {};
  var length = 0;
  var decodedTrials = var_int.decode(buf);
  decoded.nonceTrialsPerByte = decodedTrials.value;
  length += decodedTrials.length;
  var decodedExtraBytes = var_int.decode(decodedTrials.rest);
  decoded.payloadLengthExtraBytes = decodedExtraBytes.value;
  length += decodedExtraBytes.length;
  var decodedSigLength = var_int.decode(decodedExtraBytes.rest);
  decoded.signature = decodedSigLength.rest.slice(0, decodedSigLength.value);
  var siglen = decodedSigLength.length + decodedSigLength.value;
  length += siglen;
  decoded._siglen = siglen;  // Internal value
  decoded.length = length;
  return decoded;
}

/**
 * `pubkey` object.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#pubkey}
 * @namespace
 * @static
 */
var pubkey = exports.pubkey = {
  /**
   * Decode `pubkey` object message.
   * @param {Buffer} buf - Message
   * @param {?Object} opts - Decoding options
   * @return {Promise.<Object>} A promise that contains decoded `pubkey`
   * object structure when fulfilled.
   */
  decodeAsync: function(buf, opts) {
    return new promise(function(resolve) {
      var decoded = message.decode(buf);
      assert(decoded.command === "object", "Bad command");
      resolve(pubkey.decodePayloadAsync(decoded.payload, opts));
    });
  },

  /**
   * Decode `pubkey` object message payload.
   * @param {Buffer} buf - Message payload
   * @param {?Object} opts - Decoding options
   * @return {Promise.<Object>} A promise that contains decoded `pubkey`
   * object structure when fulfilled.
   */
  decodePayloadAsync: function(buf, opts) {
    return new promise(function(resolve, reject) {
      opts = opts || {};
      var neededPubkeys = opts.neededPubkeys || {};
      var decoded = object.decodePayload(buf);
      assert(decoded.type === object.PUBKEY, "Wrong object type");
      var objectPayload = decoded.objectPayload;
      delete decoded.objectPayload;
      var version = decoded.version;
      assert(version >= 2, "Address version is too low");
      assert(version <= 4, "Address version is too high");
      var siglen, sig, dataToVerify, pubkeyp;
      var addr, addrs, tag, pubkeyEncPrivateKey, dataToDecrypt;
      var length = 132;

      // v2 pubkey.
      if (version === 2) {
        // 4 + 64 + 64
        assert(
          objectPayload.length === 132,
          "Bad pubkey v2 object payload length");
        objectAssign(decoded, extractPubkeyV2(objectPayload));
        // Real data length.
        decoded.length = length;
        return resolve(decoded);
      }

      // v3 pubkey.
      if (version === 3) {
        // 4 + 64 + 64 + (1+) + (1+) + (1+)
        assert(
          objectPayload.length >= 135,
          "Bad pubkey v3 object payload length");
        objectAssign(decoded, extractPubkeyV2(objectPayload));
        objectAssign(decoded, extractPubkeyV3(objectPayload.slice(132)));
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

      assert(objectPayload.length >= 32, "Bad pubkey v4 object payload length");
      tag = decoded.tag = objectPayload.slice(0, 32);
      pubkeyEncPrivateKey = neededPubkeys[tag];
      if (!pubkeyEncPrivateKey) {
        return reject(new Error("You are not interested in this pubkey v4"));
      }
      dataToDecrypt = objectPayload.slice(32);
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
          // Since data is encrypted, entire object payload is used.
          decoded.length = objectPayload.length;
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
   * Encode `pubkey` object message.
   * @param {Object} opts - `pubkey` object options
   * @return {Promise.<Buffer>} A promise that contains encoded message
   * when fulfilled.
   */
  encodeAsync: function(opts) {
    return pubkey.encodePayloadAsync(opts).then(function(payload) {
      return message.encode("object", payload);
    });
  },

  /**
   * Encode `pubkey` object message payload.
   * @param {Object} opts - `pubkey` object options
   * @return {Promise.<Buffer>} A promise that contains encoded message
   * payload when fulfilled.
   */
  // FIXME(Kagami): Do a POW.
  encodePayloadAsync: function(opts) {
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
        opts.objectPayload = Buffer.concat([
          from.behavior.buffer,
          from.signPublicKey.slice(1),
          from.encPublicKey.slice(1),
        ]);
        obj = object.encodePayloadWithoutNonce(opts);
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
        opts.objectPayload = Buffer.concat(pubkeyData);
        obj = object.encodePayloadWithoutNonce(opts);
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
      opts.objectPayload = from.getTag();
      obj = object.encodePayloadWithoutNonce(opts);
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
