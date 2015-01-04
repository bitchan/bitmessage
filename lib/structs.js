/**
 * Implements common structures.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Common_structures}
 * @module bitmessage/structs
 */

"use strict";

require("object.assign").shim();
var assert = require("assert");
var bufferEqual = require("buffer-equal");
var bmcrypto = require("./crypto");

function isAscii(str) {
  for (var i = 0; i < str.length; i++) {
    if (str.charCodeAt(i) > 127) {
      return false;
    }
  }
  return true;
}

function getchecksum(data) {
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
   * @param {Buffer} buf - Buffer that starts with encoded message
   * structure
   * @return {{command: string, payload: Buffer, length: number, rest: Buffer}}
   * Decoded message structure.
   */
  decode: function(buf) {
    assert(buf.length >= 24, "Buffer is too small");
    assert(buf.readUInt32BE(0, true) === message.MAGIC, "Wrong magic");
    var command = buf.slice(4, 16);
    var firstNonNull;
    for (var i = 11; i >=0; i--) {
      assert(command[i] <= 127, "Non-ASCII characters in command");
      if (firstNonNull === undefined && command[i] !== 0) {
        firstNonNull = i;
      }
    }
    command = command.slice(0, firstNonNull + 1).toString("ascii");
    var payloadLength = buf.readUInt32BE(16, true);
    assert(payloadLength <= 262144, "Payload is too big");
    var checksum = buf.slice(20, 24);
    var length = 24 + payloadLength;
    var payload = buf.slice(24, length);
    assert(bufferEqual(checksum, getchecksum(payload)), "Bad checkum");
    var rest = buf.slice(length);
    return {command: command, payload: payload, length: length, rest: rest};
  },

  /**
   * Encode message structure.
   * @param {string} command - ASCII string identifying the packet
   * content
   * @param {Buffer} payload - The actual data, a message or an object
   * @return {Buffer} Encoded message structure.
   */
  encode: function(command, payload) {
    assert(command.length <= 12, "Command is too long");
    assert(isAscii(command), "Non-ASCII characters in command");
    assert(payload.length <= 262144, "Payload is too big");
    var buf = new Buffer(24 + payload.length);
    buf.fill(0);
    buf.writeUInt32BE(message.MAGIC, 0, true);
    buf.write(command, 4);
    buf.writeUInt32BE(payload.length, 16, true);
    getchecksum(payload).copy(buf, 20);
    payload.copy(buf, 24);
    return buf;
  },
};


/**
 * var_int.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Variable_length_integer}
 * @namespace
 * @static
 */
var var_int = exports.var_int = {
  /**
   * Decode var_int.
   * @param {Buffer} buf - A buffer that starts with encoded var_int
   * @return {{value: number, length: number, rest: Buffer}}
   * Decoded var_int structure.
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
   * Encode number into var_int.
   * @param {(number|Buffer)} value - Input number
   * @return {Buffer} Encoded var_int.
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
      throw new Error("Value encode error");
    }
    return buf;
  },
};

/**
 * var_str.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Variable_length_string}
 * @namespace
 */
exports.var_str = {
  /**
   * Decode var_str.
   * @param {Buffer} buf - A buffer that starts with encoded var_str
   * @return {{str: string, length: number, rest: Buffer}}
   * Decoded var_str structure.
   */
  decode: function(buf) {
    var decoded = var_int.decode(buf);
    var strLength = decoded.value;
    // XXX(Kagami): Spec doesn't mention encoding, using UTF-8.
    var str = decoded.rest.slice(0, strLength).toString();
    var rest = decoded.rest.slice(strLength);
    return {str: str, length: decoded.length + strLength, rest: rest};
  },

  /**
   * Encode string into var_str.
   * @param {string} str - A string
   * @return {Buffer} Encoded var_str.
   */
  encode: function(str) {
    // XXX(Kagami): Spec doesn't mention encoding, using UTF-8.
    var strBuf = new Buffer(str);
    return Buffer.concat([var_int.encode(strBuf.length), strBuf]);
  },
};

/**
 * var_int_list.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Variable_length_list_of_integers}
 * @namespace
 */
exports.var_int_list = {
  /**
   * Decode var_int_list.
   * @param {Buffer} buf - A buffer that starts with encoded
   * var_int_list
   * @return {{list: number[], length: number, rest: Buffer}}
   * Decoded var_int_list structure.
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
   * Encode list of numbers into var_int_list.
   * @param {number[]} list - A number list
   * @return {Buffer} Encoded var_int_list.
   */
  encode: function(list) {
    var listBuf = Buffer.concat(list.map(var_int.encode));
    return Buffer.concat([var_int.encode(list.length), listBuf]);
  },
};

exports.messageEncodings = Object.create(var_int);
Object.assign(exports.messageEncodings, {
  IGNORE: 0,
  TRIVIAL: 1,
  SIMPLE: 2,
});

exports.serviceFeatures = {
  NODE_NETWORK: 1,
};

exports.pubkeyFeatures = {
  INCLUDE_DESTINATION: 30,
  DOES_ACK: 31,
};
