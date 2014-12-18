/**
 * Implement `var_int` encoding/decoding.
 * @module bitmessage/varint
 */

"use strict";

// TODO(Kagami): Since `node-int64` and `int64-native` APIs are slightly
// differ, there might be need in platform-dependent wrapper. Also think
// that to do with 64bit arithmetic since `node-int64` doesn't implement
// it.
var Int64 = require("int64-native");
var assert = require("./utils").assert;

exports.decode = function(buf) {
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
      var lo = buf.readUInt32BE(5);
      value = new Int64(hi, lo);
      assert(value >= 4294967296, "Impractical var_int");
      length = 9;
      break;
    default:
      value = buf[0];
      length = 1;
  }
  var rest = buf.slice(length);
  return {value: value, length: length, rest: rest};
};
