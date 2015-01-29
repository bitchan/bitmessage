/**
 * Working with objects.
 * NOTE: Most operations with objects in this module are asynchronous
 * and return promises.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Object_types}
 * @module bitmessage/objects
 */
// TODO(Kagami): Document object-like params.
// FIXME(Kagami): Think through the API, we may want to get decoded
// structure even if it contains unsupported version. Also error
// handling may need some refactoring.

"use strict";

var objectAssign = Object.assign || require("object-assign");
var bufferEqual = require("buffer-equal");
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
      var objectPayload = util.popkey(decoded, "objectPayload");
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

// Extract pubkey data from decrypted object payload.
function extractPubkey(buf) {
  var decoded = {length: 132};
  // We assume here that input buffer was copied before so it's safe to
  // return reference to it.
  decoded.behavior = PubkeyBitfield(buf.slice(0, 4));
  var signPublicKey = decoded.signPublicKey = new Buffer(65);
  signPublicKey[0] = 4;
  buf.copy(signPublicKey, 1, 4, 68);
  var encPublicKey = decoded.encPublicKey = new Buffer(65);
  encPublicKey[0] = 4;
  buf.copy(encPublicKey, 1, 68, 132);
  return decoded;
}

// Extract pubkey version 3 data from decrypted object payload.
function extractPubkeyV3(buf) {
  var decoded = extractPubkey(buf);
  var decodedTrials = var_int.decode(buf.slice(132));
  decoded.nonceTrialsPerByte = decodedTrials.value;
  decoded.length += decodedTrials.length;
  var decodedExtraBytes = var_int.decode(decodedTrials.rest);
  decoded.payloadLengthExtraBytes = decodedExtraBytes.value;
  decoded.length += decodedExtraBytes.length;
  var decodedSigLength = var_int.decode(decodedExtraBytes.rest);
  var siglen = decodedSigLength.value;
  var rest = decodedSigLength.rest;
  assert(rest.length >= siglen, "Bad pubkey object payload length");
  decoded.signature = rest.slice(0, siglen);
  siglen += decodedSigLength.length;
  decoded._siglen = siglen;  // Internal value
  decoded.length += siglen;
  return decoded;
}

function findPubkeyPrivateKey(neededPubkeys, tag) {
  // `neededPubkeys` is either single address or addresses array or
  // Object key-by-tag. Time to match the tag is O(1), O(n), O(1)
  // respectfully.
  neededPubkeys = neededPubkeys || {};
  var addr, addrs, i;
  if (Address.isAddress(neededPubkeys)) {
    addr = neededPubkeys;
    if (bufferEqual(addr.getTag(), tag)) {
      return addr.getPubkeyPrivateKey();
    }
  } else if (Array.isArray(neededPubkeys)) {
    addrs = neededPubkeys;
    for (i = 0; i < addrs.length; i++) {
      if (bufferEqual(addrs[i].getTag(), tag)) {
        return addrs[i].getPubkeyPrivateKey();
      }
    }
  } else {
    return neededPubkeys[tag];
  }
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
   * @param {?(Address[]|Address|Object)} opts.needed - Address objects
   * which represent pubkeys that we are interested in. This is used
   * only for pubkeys v4. `needed` is either single address or addresses
   * array or Object key-by-tag. Time to match the tag is O(1), O(n),
   * O(1) respectfully.
   * @return {Promise.<Object>} A promise that contains decoded `pubkey`
   * object structure when fulfilled.
   */
  decodePayloadAsync: function(buf, opts) {
    return new promise(function(resolve) {
      opts = opts || {};
      var decoded = object.decodePayload(buf);
      assert(decoded.type === object.PUBKEY, "Wrong object type");
      var version = decoded.version;
      assert(version >= 2, "Address version is too low");
      assert(version <= 4, "Address version is too high");
      var objectPayload = util.popkey(decoded, "objectPayload");
      var siglen, pos, sig, dataToVerify, pubkeyp;
      var tag, pubkeyPrivateKey, dataToDecrypt;

      // v2 pubkey.
      if (version === 2) {
        // 4 + 64 + 64
        assert(
          objectPayload.length === 132,
          "Bad pubkey v2 object payload length");
        objectAssign(decoded, extractPubkey(objectPayload));
        return resolve(decoded);
      }

      // v3 pubkey.
      if (version === 3) {
        // 4 + 64 + 64 + (1+) + (1+) + (1+)
        assert(
          objectPayload.length >= 135,
          "Bad pubkey v3 object payload length");
        objectAssign(decoded, extractPubkeyV3(objectPayload));
        siglen = util.popkey(decoded, "_siglen");
        pos = decoded.headerLength + decoded.length - siglen;
        // Object message payload from `expiresTime` up to `sig_length`.
        dataToVerify = buf.slice(8, pos);
        sig = decoded.signature;
        pubkeyp = bmcrypto.verify(decoded.signPublicKey, dataToVerify, sig)
          .then(function() {
            return decoded;
          });
        return resolve(pubkeyp);
      }

      // v4 pubkey.
      assert(objectPayload.length >= 32, "Bad pubkey v4 object payload length");
      tag = decoded.tag = objectPayload.slice(0, 32);
      pubkeyPrivateKey = findPubkeyPrivateKey(opts.needed, tag);
      assert(pubkeyPrivateKey, "You are not interested in this pubkey v4");
      dataToDecrypt = objectPayload.slice(32);
      pubkeyp = bmcrypto
        .decrypt(pubkeyPrivateKey, dataToDecrypt)
        .then(function(decrypted) {
          // 4 + 64 + 64 + (1+) + (1+) + (1+)
          assert(
            decrypted.length >= 135,
            "Bad pubkey v4 object payload length");
          objectAssign(decoded, extractPubkeyV3(decrypted));
          siglen = util.popkey(decoded, "_siglen");
          dataToVerify = Buffer.concat([
            // Object header without nonce + tag.
            buf.slice(8, decoded.headerLength + 32),
            // Unencrypted pubkey data without signature.
            decrypted.slice(0, decoded.length - siglen),
          ]);
          sig = decoded.signature;
          // Since data is encrypted, entire object payload is used.
          decoded.length = objectPayload.length;
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

// Try to decrypt message with all provided identities.
function tryDecryptMsg(identities, buf) {
  function inner(i) {
    if (i > last) {
      return promise.reject("Failed to decrypt msg with given identities");
    }
    return bmcrypto
      .decrypt(identities[i].encPrivateKey, buf)
      .then(function(decrypted) {
        return {addr: identities[i], decrypted: decrypted};
      }).catch(function() {
        return inner(i + 1);
      });
  }

  var last = identities.length - 1;
  return inner(0);
}

// Encode message from the given options.
function encodeMessage(opts) {
  var encoding = opts.encoding || DEFAULT_ENCODING;
  var message = opts.message;
  var subject = opts.subject;
  if (encoding === msg.IGNORE && !message) {
    // User may omit message for IGNORE encoding.
    message = new Buffer(0);
  } else if (!Buffer.isBuffer(message)) {
    // User may specify message as a string.
    message = new Buffer(message, "utf8");
  }
  if (encoding === msg.SIMPLE && subject) {
    // User may specify subject for SIMPLE encoding.
    if (!Buffer.isBuffer(subject)) {
      subject = new Buffer(subject, "utf8");
    }
    message = Buffer.concat([
      new Buffer("Subject:"),
      subject,
      new Buffer("\nBody:"),
      message,
    ]);
  }
  return message;
}

// Decode message to the given encoding.
function decodeMessage(message, encoding) {
  var decoded = {};
  if (encoding === msg.TRIVIAL || encoding === msg.SIMPLE) {
    message = message.toString("utf8");
  }
  if (encoding !== msg.SIMPLE) {
    decoded.message = message;
    return decoded;
  }

  // SIMPLE.
  var subject, index;
  if (message.slice(0, 8) === "Subject:") {
    subject = message.slice(8);
    index = subject.indexOf("\nBody:");
    if (index !== -1) {
      message = subject.slice(index + 6);
      subject = subject.slice(0, index);
    } else {
      message = "";
    }
    decoded.subject = subject;
    decoded.message = message;
  } else {
    decoded.subject = "";
    decoded.message = message;
  }
  return decoded;
}

/**
 * `msg` object.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#msg}
 * @namespace
 * @static
 */
var msg = exports.msg = {
  /**
   * Any data with this number may be ignored. The sending node might
   * simply be sharing its public key with you.
   */
  IGNORE: 0,
  /**
   * UTF-8. No 'Subject' or 'Body' sections. Useful for simple strings
   * of data, like URIs or magnet links.
   */
  TRIVIAL: 1,
  /**
   * UTF-8. Uses 'Subject' and 'Body' sections. No MIME is used.
   */
  SIMPLE: 2,

  /**
   * Decode `msg` object message.
   * @param {Buffer} buf - Message
   * @param {?Object} opts - Decoding options
   * @return {Promise.<Object>} A promise that contains decoded `msg`
   * object structure when fulfilled.
   */
  decodeAsync: function(buf, opts) {
    return new promise(function(resolve) {
      var decoded = message.decode(buf);
      assert(decoded.command === "object", "Bad command");
      resolve(msg.decodePayloadAsync(decoded.payload, opts));
    });
  },

  /**
   * Decode `msg` object message payload.
   * @param {Buffer} buf - Message payload
   * @param {Object} opts - Decoding options
   * @param {(Address[]|Address)} opts.identities - Address objects used
   * to decrypt the message
   * @return {Promise.<Object>} A promise that contains decoded `msg`
   * object structure when fulfilled.
   */
  decodePayloadAsync: function(buf, opts) {
    return new promise(function(resolve) {
      var identities = opts.identities;
      if (Address.isAddress(identities)) {
        identities = [identities];
      }
      var decoded = object.decodePayload(buf);
      assert(decoded.type === object.MSG, "Bad object type");
      assert(decoded.version === 1, "Bad msg version");
      var objectPayload = util.popkey(decoded, "objectPayload");

      var msgp = tryDecryptMsg(identities, objectPayload)
        .then(function(decInfo) {
          var decrypted = decInfo.decrypted;

          // Version, stream.
          // TODO(Kagami): Validate version range?
          var decodedVersion = var_int.decode(decrypted);
          decoded.senderVersion = decodedVersion.value;
          var decodedStream = var_int.decode(decodedVersion.rest);
          decoded.senderStream = decodedStream.value;

          // Behavior, keys.
          assert(
            decodedStream.rest.length >= 132,
            "Bad msg object payload length");
          objectAssign(decoded, extractPubkey(decodedStream.rest));
          decoded.length += decodedVersion.length + decodedStream.length;
          var rest = decrypted.slice(decoded.length);

          // Pow extra.
          if (decoded.senderVersion >= 3) {
            var decodedTrials = var_int.decode(rest);
            decoded.nonceTrialsPerByte = decodedTrials.value;
            decoded.length += decodedTrials.length;
            var decodedExtraBytes = var_int.decode(decodedTrials.rest);
            decoded.payloadLengthExtraBytes = decodedExtraBytes.value;
            decoded.length += decodedExtraBytes.length;
            rest = decodedExtraBytes.rest;
          }

          // Ripe, encoding.
          assert(rest.length >= 20, "Bad msg object payload length");
          decoded.ripe = rest.slice(0, 20);
          assert(
            bufferEqual(decoded.ripe, decInfo.addr.ripe),
            "msg was decrypted but the destination ripe differs");
          decoded.length += 20;
          var decodedEncoding = var_int.decode(rest.slice(20));
          var encoding = decoded.encoding = decodedEncoding.value;
          decoded.length += decodedEncoding.length;

          // Message.
          var decodedMsgLength = var_int.decode(decodedEncoding.rest);
          var msglen = decodedMsgLength.value;
          rest = decodedMsgLength.rest;
          assert(rest.length >= msglen, "Bad msg object payload length");
          decoded.length += decodedMsgLength.length + msglen;
          var message = rest.slice(0, msglen);
          objectAssign(decoded, decodeMessage(message, encoding));

          // Acknowledgement data.
          // TODO(Kagami): Validate ack, check a POW.
          var decodedAckLength = var_int.decode(rest.slice(msglen));
          var acklen = decodedAckLength.value;
          rest = decodedAckLength.rest;
          assert(rest.length >= acklen, "Bad msg object payload length");
          decoded.length += decodedAckLength.length + acklen;
          decoded.ack = rest.slice(0, acklen);

          // Signature.
          var decodedSigLength = var_int.decode(rest.slice(acklen));
          var siglen = decodedSigLength.value;
          rest = decodedSigLength.rest;
          assert(rest.length >= siglen, "Bad msg object payload length");
          var sig = decoded.signature = rest.slice(0, siglen);

          // Verify signature.
          var dataToVerify = Buffer.concat([
            // Object header without nonce.
            buf.slice(8, decoded.headerLength),
            // Unencrypted pubkey data without signature.
            decrypted.slice(0, decoded.length),
          ]);
          // Since data is encrypted, entire object payload is used.
          decoded.length = objectPayload.length;
          return bmcrypto.verify(decoded.signPublicKey, dataToVerify, sig);
        }).then(function() {
          return decoded;
        });
      resolve(msgp);
    });
  },

  /**
   * Encode `msg` object message.
   * @param {Object} opts - `msg` object options
   * @return {Promise.<Buffer>} A promise that contains encoded message
   * when fulfilled.
   */
  encodeAsync: function(opts) {
    return msg.encodePayloadAsync(opts).then(function(payload) {
      return message.encode("object", payload);
    });
  },

  /**
   * Encode `msg` object message payload.
   * @param {Object} opts - `msg` object options
   * @return {Promise.<Buffer>} A promise that contains encoded message
   * payload when fulfilled.
   */
  // FIXME(Kagami): Do a POW.
  encodePayloadAsync: function(opts) {
    return new promise(function(resolve) {
      // Deal with options.
      opts = objectAssign({}, opts);
      opts.type = object.MSG;
      opts.version = 1;  // The only known msg version
      var from = Address.decode(opts.from);
      var to = Address.decode(opts.to);
      opts.stream = to.stream;
      var nonceTrialsPerByte, payloadLengthExtraBytes;
      if (from.version >= 3) {
        if (opts.friend) {
          nonceTrialsPerByte = util.DEFAULT_TRIALS_PER_BYTE;
          payloadLengthExtraBytes = util.DEFAULT_EXTRA_BYTES;
        } else {
          nonceTrialsPerByte = util.getTrials(from);
          payloadLengthExtraBytes = util.getExtraBytes(from);
        }
      }
      var encoding = opts.encoding || DEFAULT_ENCODING;
      var message = encodeMessage(opts);

      // Assemble the unencrypted message data.
      var msgData = [
        var_int.encode(from.version),
        var_int.encode(from.stream),
        from.behavior.buffer,
        from.signPublicKey.slice(1),
        from.encPublicKey.slice(1),
      ];
      if (from.version >= 3) {
        msgData.push(
          var_int.encode(nonceTrialsPerByte),
          var_int.encode(payloadLengthExtraBytes)
        );
      }
      msgData.push(
        to.ripe,
        var_int.encode(encoding),
        var_int.encode(message.length),
        message
      );
      // TODO(Kagami): Calculate ACK.
      msgData.push(var_int.encode(0));

      // Sign and encrypt.
      opts.objectPayload = new Buffer(0);
      var obj = object.encodePayloadWithoutNonce(opts);
      var dataToSign = Buffer.concat([obj].concat(msgData));
      var msgp = bmcrypto
        .sign(from.signPrivateKey, dataToSign)
        .then(function(sig) {
          var dataToEnc = msgData.concat(var_int.encode(sig.length), sig);
          dataToEnc = Buffer.concat(dataToEnc);
          return bmcrypto.encrypt(to.encPublicKey, dataToEnc);
        }).then(function(enc) {
          // POW calculation here.
          var nonce = new Buffer(8);
          // Concat object header with ecnrypted data and we are done.
          return Buffer.concat([nonce, obj, enc]);
        });
      resolve(msgp);
    });
  },
};

var DEFAULT_ENCODING = msg.TRIVIAL;
