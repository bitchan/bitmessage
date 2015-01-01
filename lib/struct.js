/**
 * Implements core structures.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Common_structures}
 * @module bitmessage/struct
 */

"use strict";

var assert = require("assert");
var bitmessage = require("./");

/**
 * var_int.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Variable_length_integer}
 */
exports.var_int = {
  /**
   * Decode var_int.
   * @param {Buffer} buf - Buffer that starts with encoded var_int
   * @return {{value: (number|Int64), length: number, rest: number}}
   * Decoded var_int structure.
   */
  decode: function(buf) {
    assert(buf.length > 0, "Empty buffer");
    var value, length;
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
        var lo = buf.readUInt32BE(5);
        value = new bitmessage.Int64(hi, lo);
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
   * @param {(number|Int64|Buffer)} value - Input number
   * @return {Buffer} Encoded var_int.
   */
  encode: function(value) {
    var buf, buf64, targetStart;
    if (typeof value === "number") {
      assert(value >= 0, "Value cannot be less than zero");
      if (value < 253) {
        buf = new Buffer([value]);
      } else if (value < 65536) {
        buf = new Buffer(3);
        buf[0] = 253;
        buf.writeUInt16BE(value, 1);
      } else if (value < 4294967296) {
        buf = new Buffer(5);
        buf[0] = 254;
        buf.writeUInt32BE(value, 1);
      } else {
        // Value may be inaccurate (max safe int = 2^53) but we will still
        // try to convert it.
        buf = new Buffer(9);
        buf[0] = 255;
        buf.writeUInt32BE(Math.floor(value / 4294967296), 1);  // high32
        buf.writeUInt32BE(value % 4294967296, 5);  // low32
      }
    } else {
      if (value.high32 && value.low32) {
        // int64-native instance.
        buf = new Buffer(9);
        buf[0] = 255;
        buf.writeUInt32BE(value.high32(), 1);
        buf.writeUInt32BE(value.low32(), 5);
      } else {
        // Try to convert to buffer.
        if (Buffer.isBuffer(value)) {
          buf64 = value;
        } else if (value.toBuffer) {
          // node-int64 instance, rawBuffer = true (prevents extra buffer
          // allocation since we copy it's value to new buffer anyway).
          buf64 = value.toBuffer(true);
        } else {
          throw new Error("Value encode error");
        }
        assert(buf64.length <= 8, "Buffer too big");
        buf = new Buffer(9);
        buf.fill(0);
        buf[0] = 255;
        targetStart = 1 + (8 - buf64.length);
        buf64.copy(buf, targetStart);
      }
    }
    return buf;
  },
};
