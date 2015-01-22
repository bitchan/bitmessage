// NOTE(Kagami): End-users shouldn't use this module. While it exports
// some helper routines, its API is _not_ stable.

"use strict";

var assert = exports.assert = function(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
};

exports.PROTOCOL_VERSION = 3;

// Missing methods to read/write 64 bits integers from/to buffers.
// TODO(Kagami): Use this helpers in structs, pow, platform.

var MAX_SAFE_INTEGER = exports.MAX_SAFE_INTEGER = 9007199254740991;

exports.readUInt64BE = function(buf, offset, noAssert) {
  offset = offset || 0;
  var hi = buf.readUInt32BE(offset, noAssert);
  var lo = buf.readUInt32BE(offset + 4, noAssert);
  // Max safe number = 2^53 - 1 =
  // 0b0000000000011111111111111111111111111111111111111111111111111111
  // = 2097151*(2^32) + (2^32 - 1).
  // So it's safe until hi <= 2097151. See
  // <http://mdn.io/issafeinteger>, <https://stackoverflow.com/q/307179>
  // for details.
  assert(noAssert || hi <= 2097151, "Unsafe integer");
  return hi * 4294967296 + lo;
};

var readTimestamp64BE = exports.readTimestamp64BE = function(buf, offset) {
  offset = offset || 0;
  var timeHi = buf.readUInt32BE(offset);
  var timeLo = buf.readUInt32BE(offset + 4);
  // JavaScript's Date object can't work with timestamps higher than
  // 8640000000000 (~2^43, ~275760 year). Hope JavaScript will support
  // 64-bit numbers up to this date.
  assert(timeHi <= 2011, "Time is too high");
  assert(timeHi !== 2011 || timeLo <= 2820767744, "Time is too high");
  return timeHi * 4294967296 + timeLo;
};

exports.readTime64BE = function(buf, offset) {
  var timestamp = readTimestamp64BE(buf, offset);
  return new Date(timestamp * 1000);
};

exports.writeUInt64BE = function(buf, value, offset, noAssert) {
  buf = buf || new Buffer(8);
  offset = offset || 0;
  assert(noAssert || value <= MAX_SAFE_INTEGER, "Unsafe integer");
  buf.writeUInt32BE(Math.floor(value / 4294967296), offset, noAssert);
  buf.writeUInt32BE(value % 4294967296, offset + 4, noAssert);
  return buf;
};
var writeUInt64BE = exports.writeUInt64BE;

exports.writeTime64BE = function(buf, time, offset, noAssert) {
  var timestamp = Math.floor(time.getTime() / 1000);
  return writeUInt64BE(buf, timestamp, offset, noAssert);
};

exports.tnow = function() {
  var time = new Date();
  return Math.floor(time.getTime() / 1000);
};

var DEFAULT_TRIALS_PER_BYTE = 1000;
var DEFAULT_EXTRA_BYTES = 1000;

exports.getTrials = function(opts) {
  var nonceTrialsPerByte = opts.nonceTrialsPerByte;
  // Automatically raise lower values per spec.
  if (!nonceTrialsPerByte || nonceTrialsPerByte < DEFAULT_TRIALS_PER_BYTE) {
    nonceTrialsPerByte = DEFAULT_TRIALS_PER_BYTE;
  }
  return nonceTrialsPerByte;
};

exports.getExtraBytes = function(opts) {
  var payloadLengthExtraBytes = opts.payloadLengthExtraBytes;
  // Automatically raise lower values per spec.
  if (!payloadLengthExtraBytes ||
      payloadLengthExtraBytes < DEFAULT_EXTRA_BYTES) {
    payloadLengthExtraBytes = DEFAULT_EXTRA_BYTES;
  }
  return payloadLengthExtraBytes;
};

exports.popkey = function(obj, key) {
  var value = obj[key];
  delete obj[key];
  return value;
};
