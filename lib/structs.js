/**
 * Implements common structures.
 * @see {@link
 * https://bitmessage.org/wiki/Protocol_specification#Common_structures}
 * @module bitmessage/structs
 * @example
 * var structs = require("bitmessage").structs;
 *
 * var encoded = Buffer.concat([
 *   structs.var_int.encode(4),
 *   Buffer("test"),
 *   structs.var_str.encode("test2"),
 *   structs.var_int_list.encode([1, 2, 3]),
 * ]);
 *
 * var decoded1 = structs.var_str.decode(encoded);
 * console.log(decoded1.str);  // test
 * var decoded2 = structs.var_str.decode(decoded1.rest);
 * console.log(decoded2.str);  // test2
 * var decoded3 = structs.var_int.decode(decoded2.rest);
 * console.log(decoded3.value);  // 3
 * var decoded4 = structs.var_int_list.decode(decoded2.rest);
 * console.log(decoded4.list);  // [1, 2, 3]
 */

"use strict";

var objectAssign = Object.assign || require("object-assign");
var bufferEqual = require("buffer-equal");
var assert = require("./_util").assert;
var bmcrypto = require("./crypto");
var POW = require("./pow");
var util = require("./_util");

function isAscii(str) {
  for (var i = 0; i < str.length; i++) {
    if (str.charCodeAt(i) > 127) {
      return false;
    }
  }
  return true;
}

// Compute the message checksum for the given data.
function getmsgchecksum(data) {
  return bmcrypto.sha512(data).slice(0, 4);
}

// \ :3 /
function findMagic(buf) {
  var i;
  var len = buf.length;
  var firstb = false;
  var secondb = false;
  var thirdb = false;
  for (i = 0; i < len; ++i) {
    switch (buf[i]) {
      case 0xE9:
        firstb = true;
        break;
      case 0xBE:
        if (firstb) { secondb = true; }
        break;
      case 0xB4:
        if (firstb && secondb) { thirdb = true; }
        break;
      case 0xD9:
        if (firstb && secondb && thirdb) { return i - 3; }
        break;
      default:
        firstb = false;
        secondb = false;
        thirdb = false;
    }
  }
  // If we reached the end of the buffer but part of the magic matches
  // we'll still return index of the magic's start position.
  if (firstb) {
    if (secondb) {
      --i;
    }
    if (thirdb) {
      --i;
    }
    return i - 1;  // Compensate for last i's increment
  } else {
    return -1;
  }
}

/**
 * Message structure.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Message_structure}
 * @namespace
 * @static
 */
var message = exports.message = {
  /**
   * Bitmessage magic value.
   * @constant {number}
   */
  MAGIC: 0xE9BEB4D9,

  /**
   * @typedef {Object} TryDecodeResult
   * @property {Object} message - Decoded message
   * @property {string} message.command - Message command
   * @property {Buffer} message.payload - Message payload
   * @property {number} message.length - Full message length
   * @property {Error} error - ...or decoding error
   * @property {Buffer} rest - The rest of the input buffer after
   * processing message
   * @memberof module:bitmessage/structs.message
   */

  /**
   * Decode message in "stream" mode.  
   * NOTE: message payload and `rest` are copied (so the runtime can GC
   * processed buffer data).
   * @param {Buffer} buf - Data buffer
   * @return {?TryDecodeResult}
   * [Decoded result.]{@link module:bitmessage/structs.message.TryDecodeResult}
   */
  tryDecode: function(buf) {
    if (buf.length < 24) {
      // Message is not yet fully received, just skip to next process
      // cycle.
      return;
    }
    var res = {};

    // Magic.
    var mindex = findMagic(buf);
    if (mindex !== 0) {
      if (mindex === -1) {
        res.error = new Error("Magic not found, skipping buffer data");
        res.rest = new Buffer(0);
      } else {
        res.error = new Error(
          "Magic in the middle of buffer, skipping some data at start"
        );
        res.rest = new Buffer(buf.length - mindex);
        buf.copy(res.rest, 0, mindex);
      }
      return res;
    }

    // Payload length.
    var payloadLength = buf.readUInt32BE(16, true);
    var msgLength = 24 + payloadLength;
    // See: <https://github.com/Bitmessage/PyBitmessage/issues/767>.
    if (payloadLength > 1600003) {
      res.error = new Error("Message is too large, skipping it");
      if (buf.length > msgLength) {
        res.rest = new Buffer(buf.length - msgLength);
        buf.copy(res.rest, 0, msgLength);
      } else {
        res.rest = new Buffer(0);
      }
      return res;
    }
    if (buf.length < msgLength) {
      // Message is not yet fully received, just skip to next process
      // cycle.
      return;
    }

    // Now we can set `rest` value.
    res.rest = new Buffer(buf.length - msgLength);
    buf.copy(res.rest, 0, msgLength);

    // Command.
    var command = buf.slice(4, 16);
    var firstNonNull = 0;
    var i;
    for (i = 11; i >=0; i--) {
      if (command[i] > 127) {
        res.error = new Error(
          "Non-ASCII characters in command, skipping message"
        );
        return res;
      }
      if (!firstNonNull && command[i] !== 0) {
        firstNonNull = i + 1;
      }
    }
    command = command.slice(0, firstNonNull).toString("ascii");

    // Payload.
    var payload = new Buffer(payloadLength);
    buf.copy(payload, 0, 24, msgLength);
    var checksum = buf.slice(20, 24);
    if (!bufferEqual(checksum, getmsgchecksum(payload))) {
      res.error = new Error("Bad checksum, skipping message");
      return res;
    }

    res.message = {command: command, payload: payload, length: msgLength};
    return res;
  },

  /**
   * @typedef {Object} DecodeResult
   * @property {string} command - Message command
   * @property {Buffer} payload - Message payload
   * @property {number} length - Full message length
   * @property {Buffer} rest - The rest of the input buffer
   * @memberof module:bitmessage/structs.message
   */

  /**
   * Decode message.  
   * NOTE: `payload` is copied, `rest` references input buffer.
   * @param {Buffer} buf - Buffer that starts with encoded message
   * @return {DecodeResult}
   * [Decoded message structure.]{@link module:bitmessage/structs.message.DecodeResult}
   */
  decode: function(buf) {
    assert(buf.length >= 24, "Buffer is too small");
    assert(buf.readUInt32BE(0, true) === message.MAGIC, "Wrong magic");
    var command = buf.slice(4, 16);
    var firstNonNull = 0;
    for (var i = 11; i >=0; i--) {
      assert(command[i] <= 127, "Non-ASCII characters in command");
      if (!firstNonNull && command[i] !== 0) {
        firstNonNull = i + 1;
      }
    }
    // NOTE(Kagami): Command can be empty.
    // NOTE(Kagami): "ascii" encoding is not necessary here since we
    // already validated the command but that should be quite faster
    // than default "utf-8" encoding.
    command = command.slice(0, firstNonNull).toString("ascii");
    var payloadLength = buf.readUInt32BE(16, true);
    assert(payloadLength <= 1600003, "Message payload is too big");
    var length = 24 + payloadLength;
    assert(buf.length >= length, "Truncated payload");
    var checksum = buf.slice(20, 24);
    // NOTE(Kagami): We do copy instead of slice to protect against
    // possible source buffer modification by user.
    var payload = new Buffer(payloadLength);
    buf.copy(payload, 0, 24, length);
    assert(bufferEqual(checksum, getmsgchecksum(payload)), "Bad checksum");
    var rest = buf.slice(length);
    return {command: command, payload: payload, length: length, rest: rest};
  },

  /**
   * Encode message.
   * @param {string} command - Message command
   * @param {Bufer} payload - Message payload
   * @return {Buffer} Encoded message structure.
   */
  encode: function(command, payload) {
    assert(command.length <= 12, "Command is too long");
    assert(isAscii(command), "Non-ASCII characters in command");
    payload = payload || new Buffer(0);
    assert(payload.length <= 1600003, "Message payload is too big");
    var buf = new Buffer(24 + payload.length);
    buf.fill(0);
    buf.writeUInt32BE(message.MAGIC, 0, true);
    buf.write(command, 4);
    buf.writeUInt32BE(payload.length, 16, true);
    getmsgchecksum(payload).copy(buf, 20);
    payload.copy(buf, 24);
    return buf;
  },
};

/**
 * An `object` is a message which is shared throughout a stream. It is
 * the only message which propagates; all others are only between two
 * nodes.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#object}
 * @namespace
 * @static
 */
var object = exports.object = {
  /**
   * [getpubkey]{@link module:bitmessage/objects.getpubkey} object type.
   * @constant {number}
   */
  GETPUBKEY: 0,
  /**
   * [pubkey]{@link module:bitmessage/objects.pubkey} object type.
   * @constant {number}
   */
  PUBKEY: 1,
  /**
   * [msg]{@link module:bitmessage/objects.msg} object type.
   * @constant {number}
   */
  MSG: 2,
  /**
   * [broadcast]{@link module:bitmessage/objects.broadcast} object type.
   * @constant {number}
   */
  BROADCAST: 3,

  /**
   * @typedef {Object} DecodeResult
   * @property {Buffer} nonce - A 8-byte object nonce
   * @property {number} ttl - Time to live in seconds
   * @property {number} type - Object type
   * @property {number} version - Object version
   * @property {number} stream - Object stream
   * @property {number} headerLength - Length of the object header
   * @property {Buffer} objectPayload - Object payload
   * @memberof module:bitmessage/structs.object
   */

  /**
   * Decode `object` message.  
   * NOTE: `nonce` and `objectPayload` are copied.
   * @param {Buffer} buf - Message
   * @param {Object=} opts - Decoding options
   * @param {boolean} opts.allowExpired - Allow expired objects
   * @param {boolean} opts.skipPow - Do not validate object POW
   * @return {DecodeResult} [Decoded `object` structure.]{@link
   * module:bitmessage/structs.object.DecodeResult}
   * @throws {Error} Invalid object
   */
  decode: function(buf, opts) {
    var decoded = message.decode(buf);
    assert(decoded.command === "object", "Given message is not an object");
    return object.decodePayload(decoded.payload, opts);
  },

  /**
   * Decode `object` message payload.
   * The same as [decode]{@link module:bitmessage/structs.object.decode}.
   */
  decodePayload: function(buf, opts) {
    opts = opts || {};

    // 8 + 8 + 4 + (1+) + (1+)
    assert(buf.length >= 22, "object message payload is too small");
    assert(buf.length <= 262144, "object message payload is too big");
    var nonce;
    if (!opts._validate) {
      nonce = new Buffer(8);
      buf.copy(nonce, 0, 0, 8);
    }

    // TTL.
    var expiresTime = util.readTimestamp64BE(buf.slice(8, 16));
    var ttl = expiresTime - util.tnow();
    assert(ttl <= 2430000, "expiresTime is too far in the future");
    if (!opts.allowExpired) {
      assert(ttl >= -3600, "Object expired more than a hour ago");
    }

    // POW.
    if (!opts.skipPow) {
      // User may specify trials/payload extra options and we will
      // account in here.
      var targetOpts = objectAssign({}, opts, {ttl: ttl, payload: buf});
      var target = POW.getTarget(targetOpts);
      assert(POW.check({target: target, payload: buf}), "Insufficient POW");
    }

    var type = buf.readUInt32BE(16, true);
    var decodedVersion = var_int.decode(buf.slice(20));
    var decodedStream = var_int.decode(decodedVersion.rest);
    var headerLength = 20 + decodedVersion.length + decodedStream.length;

    if (opts._validate) { return; }

    var objectPayload = new Buffer(decodedStream.rest.length);
    decodedStream.rest.copy(objectPayload);

    return {
      nonce: nonce,
      ttl: ttl,
      type: type,
      version: decodedVersion.value,
      stream: decodedStream.value,
      headerLength: headerLength,
      objectPayload: objectPayload,
    };
  },

  /**
   * Check whether given `object` message is valid.
   * @param {Buffer} buf - Message
   * @param {Object=} opts - Any of [object.decode]{@link
   * module:bitmessage/structs.object.decode} options
   * @return {?Error} Return an error with description if object is
   * invalid.
   */
  validate: function(buf, opts) {
    var decoded;
    try {
      decoded = message.decode(buf);
    } catch(e) {
      return e;
    }
    if (decoded.command !== "object") {
      return new Error("Given message is not an object");
    }
    return object.validatePayload(decoded.payload, opts);
  },

  /**
   * Check whether `object` message payload is valid.
   * The same as [validate]{@link
   * module:bitmessage/structs.object.validate}.
   */
  validatePayload: function(buf, opts) {
    opts = objectAssign({}, opts, {_validate: true});
    try {
      object.decodePayload(buf, opts);
    } catch(e) {
      return e;
    }
  },

  /**
   * Encode `object` message.
   * @param {Object} opts - Object options
   * @param {Object} opts.nonce - A 8-byte object nonce
   * @param {number} opts.ttl - Time to live in seconds
   * @param {number} opts.type - Object type
   * @param {number} opts.version - Object version
   * @param {number=} opts.stream - Object stream (1 by default)
   * @param {Buffer} opts.objectPayload - Object payload
   * @return {Buffer} Encoded message.
   */
  encode: function(opts) {
    var payload = object.encodePayload(opts);
    return message.encode("object", payload);
  },

  /**
   * Encode `object` message payload.
   * The same as [encode]{@link module:bitmessage/structs.object.encode}.
   */
  encodePayload: function(opts) {
    // NOTE(Kagami): We do not try to calculate nonce here if it is not
    // provided because:
    // 1) It's async operation but in `structs` module all operations
    // are synchronous.
    // 2) It shouldn't be useful because almost all objects signatures
    // include object header and POW is computed for entire object so at
    // first the object header should be assembled and only then we can
    // do a POW.
    assert(opts.nonce.length === 8, "Bad nonce");
    // NOTE(Kagami): This may be a bit inefficient since we allocate
    // twice.
    return Buffer.concat([
      opts.nonce,
      object.encodePayloadWithoutNonce(opts),
    ]);
  },

  /**
   * Encode `object` message payload without leading nonce field (may be
   * useful if you are going to calculate it later).
   * @param {Object} opts - Object options
   * @param {number} opts.ttl - Time to live in seconds
   * @param {number} opts.type - Object type
   * @param {number} opts.version - Object version
   * @param {number=} opts.stream - Object stream (1 by default)
   * @param {Buffer} opts.objectPayload - Object payload
   * @return {Buffer} Encoded payload.
   */
  encodePayloadWithoutNonce: function(opts) {
    assert(opts.ttl > 0, "Bad TTL");
    assert(opts.ttl <= 2430000, "TTL may not be larger than 28 days + 3 hours");
    var expiresTime = util.tnow() + opts.ttl;
    var type = new Buffer(4);
    type.writeUInt32BE(opts.type, 0);
    var stream = opts.stream || 1;
    var obj = Buffer.concat([
      util.writeUInt64BE(null, expiresTime),
      type,
      var_int.encode(opts.version),
      var_int.encode(stream),
      opts.objectPayload,
    ]);
    assert(obj.length <= 262136, "object message payload is too big");
    return obj;
  },
};

/**
 * Variable length integer.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Variable_length_integer}
 * @namespace
 * @static
 */
var var_int = exports.var_int = {
  /**
   * @typedef {Object} DecodeResult
   * @property {number} value - Stored value
   * @property {number} length - `var_int` full length
   * @property {Buffer} rest - The rest of the input buffer
   * @memberof module:bitmessage/structs.var_int
   */

  /**
   * Decode `var_int`.  
   * NOTE: `rest` references input buffer.
   * @param {Buffer} buf - A buffer that starts with encoded `var_int`
   * @return {DecodeResult}
   * [Decoded `var_int` structure.]{@link module:bitmessage/structs.var_int.DecodeResult}
   */
  decode: function(buf) {
    var value, length;
    assert(buf.length > 0, "Empty buffer");
    switch (buf[0]) {
      case 253:
        value = buf.readUInt16BE(1);
        assert(value >= 253, "Impractical var_int");
        length = 3;
        break;
      case 254:
        value = buf.readUInt32BE(1);
        assert(value >= 65536, "Impractical var_int");
        length = 5;
        break;
      case 255:
        var hi = buf.readUInt32BE(1);
        assert(hi !== 0, "Impractical var_int");
        // Max safe number = 2^53 - 1 =
        // 0b0000000000011111111111111111111111111111111111111111111111111111
        // = 2097151*(2^32) + (2^32 - 1).
        // So it's safe until hi <= 2097151. See
        // <http://mdn.io/issafeinteger>,
        // <https://stackoverflow.com/q/307179> for details.
        // TODO(Kagami): We may want to return raw Buffer for
        // 2^53 <= value <= 2^64 - 1 range. Probably using the optional
        // argument because most of the code expect to get a number when
        // calling `var_int.decode`.
        assert(hi <= 2097151, "Unsafe integer");
        var lo = buf.readUInt32BE(5);
        value = hi * 4294967296 + lo;
        length = 9;
        break;
      default:
        value = buf[0];
        length = 1;
    }
    var rest = buf.slice(length);
    return {value: value, length: length, rest: rest};
  },

  /**
   * Encode number into `var_int`.
   * @param {(number|Buffer)} value - Input number
   * @return {Buffer} Encoded `var_int`.
   */
  encode: function(value) {
    var buf, targetStart;
    if (typeof value === "number") {
      assert(value >= 0, "Value cannot be less than zero");
      if (value < 253) {
        buf = new Buffer([value]);
      } else if (value < 65536) {
        buf = new Buffer(3);
        buf[0] = 253;
        buf.writeUInt16BE(value, 1, true);
      } else if (value < 4294967296) {
        buf = new Buffer(5);
        buf[0] = 254;
        buf.writeUInt32BE(value, 1, true);
      } else {
        assert(value <= 9007199254740991, "Unsafe integer");
        buf = new Buffer(9);
        buf[0] = 255;
        buf.writeUInt32BE(Math.floor(value / 4294967296), 1, true);  // high32
        buf.writeUInt32BE(value % 4294967296, 5, true);  // low32
      }
    } else if (Buffer.isBuffer(value)) {
      assert(value.length <= 8, "Buffer is too big");
      buf = new Buffer(9);
      buf.fill(0);
      buf[0] = 255;
      targetStart = 1 + (8 - value.length);
      value.copy(buf, targetStart);
    } else {
      throw new Error("Unknown value type");
    }
    return buf;
  },
};

/**
 * Variable length string.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Variable_length_string}
 * @namespace
 */
exports.var_str = {
  /**
   * @typedef {Object} DecodeResult
   * @property {number} str - The string itself
   * @property {number} length - `var_str` full length
   * @property {Buffer} rest - The rest of the input buffer
   * @memberof module:bitmessage/structs.var_str
   */

  /**
   * Decode `var_str`.  
   * NOTE: `rest` references input buffer.
   * @param {Buffer} buf - A buffer that starts with encoded `var_str`
   * @return {DecodeResult}
   * [Decoded `var_str` structure.]{@link module:bitmessage/structs.var_str.DecodeResult}
   */
  decode: function(buf) {
    var decoded = var_int.decode(buf);
    var strLength = decoded.value;
    var length = decoded.length + strLength;
    assert(buf.length >= length, "Buffer is too small");
    // XXX(Kagami): Spec doesn't mention encoding, using UTF-8.
    var str = decoded.rest.slice(0, strLength).toString("utf8");
    var rest = decoded.rest.slice(strLength);
    return {str: str, length: length, rest: rest};
  },

  /**
   * Encode string into `var_str`.
   * @param {string} str - A string
   * @return {Buffer} Encoded `var_str`.
   */
  encode: function(str) {
    // XXX(Kagami): Spec doesn't mention encoding, using UTF-8.
    var strBuf = new Buffer(str, "utf8");
    return Buffer.concat([var_int.encode(strBuf.length), strBuf]);
  },
};

/**
 * Variable length list of integers.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Variable_length_list_of_integers}
 * @namespace
 */
exports.var_int_list = {
  /**
   * @typedef {Object} DecodeResult
   * @property {number} list - Stored numbers
   * @property {number} length - `var_int_list` full length
   * @property {Buffer} rest - The rest of the input buffer
   * @memberof module:bitmessage/structs.var_int_list
   */

  /**
   * Decode `var_int_list`.  
   * NOTE: `rest` references input buffer.
   * @param {Buffer} buf - A buffer that starts with encoded
   * `var_int_list`
   * @return {DecodeResult}
   * [Decoded `var_int_list` structure.]{@link module:bitmessage/structs.var_int_list.DecodeResult}
   */
  decode: function(buf) {
    var decoded = var_int.decode(buf);
    var listLength = decoded.value;
    var list = new Array(listLength);
    var rest = decoded.rest;
    var sumLength = decoded.length;
    for (var i = 0; i < listLength; i++) {
      decoded = var_int.decode(rest);
      list[i] = decoded.value;
      rest = decoded.rest;
      sumLength += decoded.length;
    }
    return {list: list, length: sumLength, rest: rest};
  },

  /**
   * Encode list of numbers into `var_int_list`.
   * @param {number[]} list - A number list
   * @return {Buffer} Encoded `var_int_list`.
   */
  encode: function(list) {
    var var_ints = list.map(var_int.encode);
    var bufs = [var_int.encode(list.length)].concat(var_ints);
    return Buffer.concat(bufs);
  },
};

// See https://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses
var IPv4_MAPPING = new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255]);

// Very simple inet_ntop(3) equivalent.
function inet_ntop(buf) {
  assert(buf.length === 16, "Bad buffer size");
  // IPv4 mapped to IPv6.
  if (bufferEqual(buf.slice(0, 12), IPv4_MAPPING)) {
    return Array.prototype.join.call(buf.slice(12), ".");
  // IPv6.
  } else {
    var groups = [];
    for (var i = 0; i < 8; i++) {
      groups.push(buf.readUInt16BE(i * 2, true).toString(16));
    }
    return groups.join(":");
  }
}

// Very simple inet_pton(3) equivalent.
function inet_pton(str) {
  var buf = new Buffer(16);
  buf.fill(0);
  // IPv4-mapped IPv6.
  if (str.slice(0, 7) === "::ffff:") {
    str = str.slice(7);
  }
  // IPv4.
  if (str.indexOf(":") === -1) {
    IPv4_MAPPING.copy(buf);
    var octets = str.split(/\./g).map(function(o) {
      assert(/^\d+$/.test(o), "Bad octet");
      return parseInt(o, 10);
    });
    // Support short form from inet_aton(3) man page.
    if (octets.length === 1) {
      buf.writeUInt32BE(octets[0], 12);
    } else {
      // Check against 1000.bad.addr
      octets.forEach(function(octet) {
        assert(octet >= 0, "Bad IPv4 address");
        assert(octet <= 255, "Bad IPv4 address");
      });
      if (octets.length === 2) {
        buf[12] = octets[0];
        buf[15] = octets[1];
      } else if (octets.length === 3) {
        buf[12] = octets[0];
        buf[13] = octets[1];
        buf[15] = octets[2];
      } else if (octets.length === 4) {
        buf[12] = octets[0];
        buf[13] = octets[1];
        buf[14] = octets[2];
        buf[15] = octets[3];
      } else {
        throw new Error("Bad IPv4 address");
      }
    }
  // IPv6.
  } else {
    var dgroups = str.split(/::/g);
    // Check against 1::1::1
    assert(dgroups.length <= 2, "Bad IPv6 address");
    var groups = [];
    var i;
    if (dgroups[0]) {
      groups.push.apply(groups, dgroups[0].split(/:/g));
    }
    if (dgroups.length === 2) {
      if (dgroups[1]) {
        var splitted = dgroups[1].split(/:/g);
        var fill = 8 - (groups.length + splitted.length);
        // Check against 1:1:1:1::1:1:1:1
        assert(fill > 0, "Bad IPv6 address");
        for (i = 0; i < fill; i++) {
          groups.push(0);
        }
        groups.push.apply(groups, splitted);
      } else {
        // Check against 1:1:1:1:1:1:1:1::
        assert(groups.length <= 7, "Bad IPv6 address");
      }
    } else {
      // Check against 1:1:1
      assert(groups.length === 8, "Bad IPv6 address");
    }
    for (i = 0; i < Math.min(groups.length, 8); i++) {
      // Check against parseInt("127.0.0.1", 16) -> 295
      assert(/^[0-9a-f]+$/.test(groups[i]), "Bad group");
      buf.writeUInt16BE(parseInt(groups[i], 16), i * 2);
    }
  }
  return buf;
}

/**
 * Network address.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Network_address}
 * @namespace
 */
exports.net_addr = {
  /**
   * @typedef {Object} DecodeResult
   * @property {Date} time - Time the node was last active, not included
   * in short mode
   * @property {number} stream - Stream number of the node, not included
   * in short mode
   * @property {Object} services -
   * [Services]{@link module:bitmessage/structs.ServicesBitfield}
   * provided by the node
   * @property {string} host - IPv4/IPv6 address of the node
   * @property {number} port - Incoming port of the node
   * @memberof module:bitmessage/structs.net_addr
   */

  /**
   * Decode `net_addr`.
   * @param {Buffer} buf - A buffer that contains encoded `net_addr`
   * @param {Object=} opts - Decoding options; use `short` option to
   * decode `net_addr` from
   * [version message]{@link module:bitmessage/messages.version}
   * @return {DecodeResult}
   * [Decoded `net_addr` structure.]{@link module:bitmessage/structs.net_addr.DecodeResult}
   */
  decode: function(buf, opts) {
    var short = !!(opts || {}).short;
    var res = {};
    if (short) {
      assert(buf.length === 26, "Bad buffer size");
    } else {
      assert(buf.length === 38, "Bad buffer size");
      var timeHi = buf.readUInt32BE(0, true);
      var timeLo = buf.readUInt32BE(4, true);
      // JavaScript's Date object can't work with timestamps higher than
      // 8640000000000 (~2^43, ~275760 year). Hope JavaScript will
      // support 64-bit numbers up to this date.
      assert(timeHi <= 2011, "Time is too high");
      assert(timeHi !== 2011 || timeLo <= 2820767744, "Time is too high");
      res.time = new Date((timeHi * 4294967296 + timeLo) * 1000);
      res.stream = buf.readUInt32BE(8, true);
      buf = buf.slice(12);
    }
    res.services = ServicesBitfield(buf.slice(0, 8), {copy: true});
    res.host = inet_ntop(buf.slice(8, 24));
    res.port = buf.readUInt16BE(24, true);
    return res;
  },

  /**
   * Encode `net_addr`.
   * @param {Object} opts - Encoding options
   * @param {boolean=} opts.short - Encode `net_addr` for
   * [version message]{@link module:bitmessage/messages.version}
   * (false by default)
   * @param {Date=} opts.time - Time the node was last active, not
   * included in short mode (current time by default)
   * @param {number=} opts.stream - Stream number of the node, not
   * included in short mode (1 by default)
   * @param {Object=} opts.services -
   * [Services]{@link module:bitmessage/structs.ServicesBitfield}
   * provided by the node (`NODE_NETWORK` by default)
   * @param {string} opts.host - IPv4/IPv6 address of the node
   * @param {number} opts.port - Incoming port of the node
   * @return {Buffer} Encoded `net_addr`.
   */
  encode: function(opts) {
    // Be aware of `Buffer.slice` quirk in browserify:
    // <http://git.io/lNZF1A> (does not modify parent buffer's memory in
    // old browsers). So we use offset instead of `buf = buf.slice`.
    var buf, shift;
    if (opts.short) {
      buf = new Buffer(26);
      shift = 0;
    } else {
      buf = new Buffer(38);
      var time = opts.time || new Date();
      time = Math.floor(time.getTime() / 1000);
      buf.writeUInt32BE(Math.floor(time / 4294967296), 0, true);  // high32
      buf.writeUInt32BE(time % 4294967296, 4, true);  // low32
      var stream = opts.stream || 1;
      buf.writeUInt32BE(stream, 8);
      shift = 12;
    }
    var services = opts.services ||
                   ServicesBitfield().set(ServicesBitfield.NODE_NETWORK);
    services.buffer.copy(buf, shift);
    inet_pton(opts.host).copy(buf, shift + 8);
    buf.writeUInt16BE(opts.port, shift + 24);
    return buf;
  },
};

/**
 * Inventory vector.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Inventory_Vectors}
 * @namespace
 */
exports.inv_vect = {
  // NOTE(Kagami): Only encode operation is defined because decoding of
  // the encoded vector is impossible.

  /**
   * Encode inventory vector.
   * @param {Buffer} buf - Payload to calculate the inventory vector for
   * @return {Buffer} A 32-byte encoded `inv_vect`.
   */
  encode: function(buf) {
    return bmcrypto.sha512(bmcrypto.sha512(buf)).slice(0, 32);
  },
};

/**
 * Encrypted payload.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Encrypted_payload}
 * @namespace encrypted
 * @static
 */
/**
 * @typedef {Object} DecodeResult
 * @property {Buffer} iv - Initialization vector (16 bytes)
 * @property {Buffer} ephemPrivateKey - Ephemeral private key (32 bytes)
 * @property {Buffer} ciphertext - The result of encryption (variable
 * size)
 * @property {Buffer} mac - Message authentication code (32 bytes)
 * @memberof module:bitmessage/structs.encrypted
 */
/**
 * Decode encrypted payload.  
 * NOTE: all structure members are copied.
 * @param {Buffer} buf - A buffer that contains encrypted payload
 * @return {DecodeResult}
 * [Decoded `encrypted` structure.]{@link module:bitmessage/structs.encrypted.DecodeResult}
 * @function decode
 * @memberof module:bitmessage/structs.encrypted
 */
/**
 * Encode `encrypted`.
 * @param {Object} opts - Encoding options
 * @param {Buffer} opts.iv - Initialization vector (16 bytes)
 * @param {Buffer} opts.ephemPrivateKey - Ephemeral private key (32
 * bytes)
 * @param {Buffer} opts.ciphertext - The result of encryption (variable
 * size)
 * @param {Buffer} opts.mac - Message authentication code (32 bytes)
 * @return {Buffer} Encoded `encrypted` payload.
 * @function encode
 * @memberof module:bitmessage/structs.encrypted
 */
// Reexport struct.
exports.encrypted = bmcrypto.encrypted;

// Creates bitfield (MSB 0) class of the specified size.
var Bitfield = function(size) {
  var bytesize = size / 8;

  // Inspired by <https://github.com/fb55/bitfield>.
  function BitfieldInner(buf, opts) {
    if (!(this instanceof BitfieldInner)) {
      return new BitfieldInner(buf);
    }
    opts = opts || {};
    if (buf) {
      assert(buf.length === bytesize, "Bad buffer size");
      if (opts.copy) {
        var dup = new Buffer(bytesize);
        dup.fill(0);
        buf.copy(dup);
        buf = dup;
      }
    } else {
      buf = new Buffer(bytesize);
      buf.fill(0);
    }
    this.buffer = buf;
  }

  BitfieldInner.prototype.get = function(bits) {
    if (!Array.isArray(bits)) {
      bits = [bits];
    }
    var buf = this.buffer;
    return bits.every(function(bit) {
      assert(bit >= 0, "Bit number is too low");
      assert(bit < size, "Bit number is too high");
      var index = Math.floor(bit / 8);
      var shift = 7 - (bit % 8);
      return (buf[index] & (1 << shift)) !== 0;  // jshint ignore:line
    });
  };

  BitfieldInner.prototype.set = function(bits) {
    if (!Array.isArray(bits)) {
      bits = [bits];
    }
    var buf = this.buffer;
    bits.forEach(function(bit) {
      assert(bit >= 0, "Bit number is too low");
      assert(bit < size, "Bit number is too high");
      var index = Math.floor(bit / 8);
      var shift = 7 - (bit % 8);
      buf[index] |= 1 << shift;  // jshint ignore:line
    });
    return this;
  };

  BitfieldInner.prototype.toString = function() {
    var i;
    var str = "";
    for (i = 0; i < this.buffer.length; i++) {
      // Should be faster than pushing to array and joining on v8.
      str += ("0000000" + this.buffer[i].toString(2)).slice(-8);
    }
    return "<Bitfield:" + str + ">";
  };

  return BitfieldInner;
};

/**
 * Service features bitfield (MSB 0).
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#version}
 * @param {Buffer=} buf - A 8-byte bitfield buffer (will be created if
 * not provided or will be copied if `opts.copy` is `true`)
 * @param {Object=} opts - Options
 * @constructor
 * @static
 * @example
 * var ServicesBitfield = require("bitmessage").structs.ServicesBitfield;
 * var services = ServicesBitfield().set(ServicesBitfield.NODE_NETWORK);
 * console.log(services.get(ServicesBitfield.NODE_NETWORK));  // true
 * console.log(services.get(15));  // false
 */
// NOTE(Kagami): Since pubkey bitfield uses MSB 0, we use it here too.
// See <https://github.com/Bitmessage/PyBitmessage/issues/769> for
// details.
var ServicesBitfield = exports.ServicesBitfield = objectAssign(Bitfield(64), {
  /**
   * Returns a boolean indicating whether the bit is set.
   * @param {number} index - Bit index (MSB 0)
   * @function get
   * @instance
   * @return {boolean}
   * @memberof module:bitmessage/structs.ServicesBitfield
   */
  /**
   * Set the given bit(s) to `1`.
   * @param {(number|number[])} index - Bit(s) index (MSB 0)
   * @function set
   * @instance
   * @return {Object} Returns self so methods can be chained.
   * @memberof module:bitmessage/structs.ServicesBitfield
   */
  /**
   * The contents of the bitfield.
   * @type {Buffer}
   * @var buffer
   * @instance
   * @memberof module:bitmessage/structs.ServicesBitfield
   */

  /**
   * Bit index indicating normal network node.
   * @memberof module:bitmessage/structs.ServicesBitfield
   * @constant {number}
   */
  NODE_NETWORK: 63,
  /**
   * Bit index indicating web/mobile client with limited network
   * capabilities (proposal feature).
   * @memberof module:bitmessage/structs.ServicesBitfield
   * @see {@link https://bitmessage.org/wiki/Mobile_Protocol_specification}
   * @constant {number}
   */
  NODE_MOBILE: 62,
  /**
   * Bit index indicating node which can work as a WebSocket gateway for
   * web/mobile clients (proposal feature).
   * @memberof module:bitmessage/structs.ServicesBitfield
   * @see {@link https://bitmessage.org/wiki/Mobile_Protocol_specification}
   * @constant {number}
   */
  NODE_GATEWAY: 61,
});

/**
 * Pubkey features bitfield (MSB 0).
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Pubkey_bitfield_features}
 * @param {Buffer=} buf - A 4-byte bitfield buffer (will be created if
 * not provided or will be copied if `opts.copy` is `true`)
 * @param {Object=} opts - Options
 * @constructor
 * @example
 * var PubkeyBitfield = require("bitmessage").structs.PubkeyBitfield;
 * var behavior = PubkeyBitfield().set([
 *   PubkeyBitfield.INCLUDE_DESTINATION,
 *   PubkeyBitfield.DOES_ACK,
 * ]).set(1);
 * console.log(behavior.get(PubkeyBitfield.DOES_ACK));  // true
 * console.log(behavior.get(15));  // false
 */
exports.PubkeyBitfield = objectAssign(Bitfield(32), {
  /**
   * Returns a boolean indicating whether the bit is set.
   * @param {number} index - Bit index (MSB 0)
   * @function get
   * @instance
   * @return {boolean}
   * @memberof module:bitmessage/structs.PubkeyBitfield
   */
  /**
   * Set the given bit(s) to `1`.
   * @param {(number|number[])} index - Bit(s) index (MSB 0)
   * @function set
   * @instance
   * @return {Object} Returns self so methods can be chained.
   * @memberof module:bitmessage/structs.PubkeyBitfield
   */
  /**
   * The contents of the bitfield.
   * @type {Buffer}
   * @var buffer
   * @instance
   * @memberof module:bitmessage/structs.PubkeyBitfield
   */

  /**
   * Bit index.
   * If set, the receiving node does send acknowledgements (rather than
   * dropping them).
   * @memberof module:bitmessage/structs.PubkeyBitfield
   * @constant {number}
   */
  DOES_ACK: 31,
  /**
   * Bit index.
   * If set, the receiving node expects that the RIPEMD hash encoded in
   * their address preceedes the encrypted message data of msg messages
   * bound for them.
   * @memberof module:bitmessage/structs.PubkeyBitfield
   * @constant {number}
   */
  INCLUDE_DESTINATION: 30,
});
