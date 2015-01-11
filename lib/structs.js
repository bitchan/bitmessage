/**
 * Implements common structures.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Common_structures}
 * @module bitmessage/structs
 */
// TODO(Kagami): Find a way how to document object params properly.

"use strict";

var objectAssign = Object.assign || require("object-assign");
var bufferEqual = require("buffer-equal");
var assert = require("./util").assert;
var bmcrypto = require("./crypto");

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

/**
 * Message structure.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Message_structure}
 * @namespace
 * @static
 */
var message = exports.message = {
  /** Bitmessage magic value. */
  MAGIC: 0xE9BEB4D9,

  /**
   * Decode message structure.
   * NOTE: `payload` is copied, `rest` references input buffer.
   * @param {Buffer} buf - Buffer that starts with encoded message
   * structure
   * @return {{command: string, payload: Buffer, length: number, rest: Buffer}}
   * Decoded message structure.
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
    // Command could be empty.
    command = command.slice(0, firstNonNull).toString("ascii");
    var payloadLength = buf.readUInt32BE(16, true);
    assert(payloadLength <= 262144, "Payload is too big");
    var checksum = buf.slice(20, 24);
    var length = 24 + payloadLength;
    // NOTE(Kagami): We do copy instead of slice to protect against
    // possible source buffer modification by user.
    var payload = new Buffer(payloadLength);
    buf.copy(payload, 0, 24, length);
    assert(bufferEqual(checksum, getmsgchecksum(payload)), "Bad checkum");
    var rest = buf.slice(length);
    return {command: command, payload: payload, length: length, rest: rest};
  },

  /**
   * Encode message structure.
   * @param {{command: string, payload: Buffer}} opts - Encode options
   * @return {Buffer} Encoded message structure.
   */
  encode: function(opts) {
    assert(opts.command.length <= 12, "Command is too long");
    assert(isAscii(opts.command), "Non-ASCII characters in command");
    assert(opts.payload.length <= 262144, "Payload is too big");
    var buf = new Buffer(24 + opts.payload.length);
    buf.fill(0);
    buf.writeUInt32BE(message.MAGIC, 0, true);
    buf.write(opts.command, 4);
    buf.writeUInt32BE(opts.payload.length, 16, true);
    getmsgchecksum(opts.payload).copy(buf, 20);
    opts.payload.copy(buf, 24);
    return buf;
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
   * Decode `var_int`.
   * NOTE: `rest` references input buffer.
   * @param {Buffer} buf - A buffer that starts with encoded `var_int`
   * @return {{value: number, length: number, rest: Buffer}}
   * Decoded `var_int` structure.
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
        // 2^53 <= value <= 2^64 - 1 range. Possibly using the optional
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
   * Decode `var_str`.
   * NOTE: `rest` references input buffer.
   * @param {Buffer} buf - A buffer that starts with encoded `var_str`
   * @return {{str: string, length: number, rest: Buffer}}
   * Decoded `var_str` structure.
   */
  decode: function(buf) {
    var decoded = var_int.decode(buf);
    var strLength = decoded.value;
    var length = decoded.length + strLength;
    assert(buf.length >= length, "Buffer is too small");
    // XXX(Kagami): Spec doesn't mention encoding, using UTF-8.
    var str = decoded.rest.slice(0, strLength).toString();
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
    var strBuf = new Buffer(str);
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
   * Decode `var_int_list`.
   * NOTE: `rest` references input buffer.
   * @param {Buffer} buf - A buffer that starts with encoded
   * `var_int_list`
   * @return {{list: number[], length: number, rest: Buffer}}
   * Decoded `var_int_list` structure.
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
    var listBuf = Buffer.concat(list.map(var_int.encode));
    return Buffer.concat([var_int.encode(list.length), listBuf]);
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
  // IPv4.
  if (str.indexOf(":") === -1) {
    IPv4_MAPPING.copy(buf);
    var octets = str.split(/\./g).map(function(s) {return parseInt(s, 10);});
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
   * Decode `net_addr`.
   * @param {Buffer} buf - A buffer that contains encoded `net_addr`
   * @param {?Object} opts - Decode options
   * @return {Object} Decoded `net_addr` structure.
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
    res.services = serviceFeatures.decode(buf.slice(0, 8));
    res.host = inet_ntop(buf.slice(8, 24));
    res.port = buf.readUInt16BE(24, true);
    return res;
  },

  /**
   * Encode `net_addr`.
   * @param {Object} opts - Encode options; use `short` option to encode
   * `net_addr` used in version message
   * @return {Buffer} Encoded `net_addr`.
   */
  encode: function(opts) {
    // Be aware of `Buffer.slice` quirk in browserify:
    // <http://git.io/lNZF1A> (does not modify parent buffer's memory in
    // old browsers).
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
      buf.writeUInt32BE(opts.stream, 8);
      shift = 12;
    }
    var services = opts.services || [serviceFeatures.NODE_NETWORK];
    serviceFeatures.encode(services).copy(buf, shift);
    inet_pton(opts.host).copy(buf, shift + 8);
    buf.writeUInt16BE(opts.port, shift + 24);
    return buf;
  },
};

var SECP256K1_TYPE = 714;

/**
 * Encrypted payload.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Encrypted_payload}
 * @namespace
 */
exports.encrypted = {
  /**
   * Decode encrypted payload.
   * NOTE: all structure members are copied.
   * @param {Buffer} buf - A buffer that contains encrypted payload
   * @return {Object} Decoded encrypted structure.
   */
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
    var cipherText = new Buffer(buf.length - 118);
    buf.copy(cipherText, 0, 86, buf.length - 32);
    var mac = new Buffer(32);
    buf.copy(mac, 0, buf.length - 32);
    return {
      iv: iv,
      ephemPublicKey: ephemPublicKey,
      cipherText: cipherText,
      mac: mac,
    };
  },

  /**
   * Encode `encrypted`.
   * @param {Object} opts - Encode options
   * @return {Buffer} Encoded encrypted payload.
   */
  encode: function(opts) {
    assert(opts.iv.length === 16, "Bad IV");
    assert(opts.ephemPublicKey.length === 65, "Bad public key");
    assert(opts.mac.length === 32, "Bad MAC");
    // 16 + 2 + 2 + 32 + 2 + 32 + ? + 32
    var buf = new Buffer(118 + opts.cipherText.length);
    opts.iv.copy(buf);
    buf.writeUInt16BE(SECP256K1_TYPE, 16, true);  // Curve type
    buf.writeUInt16BE(32, 18, true);  // Rx length
    opts.ephemPublicKey.copy(buf, 20, 1, 33);  // Rx
    buf.writeUInt16BE(32, 52, true);  // Ry length
    opts.ephemPublicKey.copy(buf, 54, 33);  // Ry
    opts.cipherText.copy(buf, 86);
    opts.mac.copy(buf, 86 + opts.cipherText.length);
    return buf;
  },
};

/**
 * Message encodings. Extends {@link var_int} by adding known encoding type
 * constants.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Message_Encodings}
 * @namespace
 */
exports.messageEncodings = objectAssign(Object.create(var_int), {
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
});

// Creates bitfield class of the specified size.
var bitfield = function(size) {
  var bytesize = size / 8;
  return {
    decode: function(buf) {
      assert(buf.length === bytesize, "Bad buffer size");
      var features = [];
      var index;
      for (var i = 0; i < size; i++) {
        index = bytesize - Math.floor(i / 8) - 1;
        if ((buf[index] & (1 << (i % 8))) !== 0) {  // jshint ignore:line
          features.push(i);
        }
      }
      return features;
    },

    encode: function(features) {
      var buf = new Buffer(bytesize);
      buf.fill(0);
      features.forEach(function(feature) {
        assert(feature >= 0, "Bad feature");
        assert(feature <= (size - 1), "Bad feature");
        var index = bytesize - Math.floor(feature / 8) - 1;
        buf[index] |= 1 << (feature % 8);  // jshint ignore:line
      });
      return buf;
    },
  };
};

/**
 * Service bitfield features. Implements encoding/decoding for a 8-byte
 * buffer object.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#version}
 * @namespace
 * @static
 */
// TODO(Kagami): Document methods.
var serviceFeatures = exports.serviceFeatures = objectAssign(bitfield(64), {
  /** This is a normal network node. */
  NODE_NETWORK: 0,
});

/**
 * Pubkey bitfield features. Implements encoding/decoding for a 4-byte
 * buffer object.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Pubkey_bitfield_features}
 * @namespace
 */
// TODO(Kagami): Document methods.
exports.pubkeyFeatures = objectAssign(bitfield(32), {
  /**
   * Receiving node expects that the RIPE hash encoded in their address
   * preceedes the encrypted message data of msg messages bound for
   * them.
   */
  INCLUDE_DESTINATION: 30,
  /**
   * If true, the receiving node does send acknowledgements (rather than
   * dropping them).
   */
  DOES_ACK: 31,
});
