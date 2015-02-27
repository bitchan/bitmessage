// NOTE(Kagami): End-users shouldn't import this module. While it
// exports some helper routines, its API is _not_ stable.

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

function writeUInt64BE(buf, value, offset, noAssert) {
  buf = buf || new Buffer(8);
  offset = offset || 0;
  assert(noAssert || value <= MAX_SAFE_INTEGER, "Unsafe integer");
  buf.writeUInt32BE(Math.floor(value / 4294967296), offset, noAssert);
  buf.writeUInt32BE(value % 4294967296, offset + 4, noAssert);
  return buf;
}
exports.writeUInt64BE = writeUInt64BE;

exports.writeTime64BE = function(buf, time, offset, noAssert) {
  var timestamp = Math.floor(time.getTime() / 1000);
  return writeUInt64BE(buf, timestamp, offset, noAssert);
};

exports.tnow = function() {
  var time = new Date();
  return Math.floor(time.getTime() / 1000);
};

var DEFAULT_TRIALS_PER_BYTE = exports.DEFAULT_TRIALS_PER_BYTE = 1000;
var DEFAULT_EXTRA_BYTES = exports.DEFAULT_EXTRA_BYTES = 1000;

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

// See https://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses
var IPv4_MAPPING = new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255]);
exports.IPv4_MAPPING = IPv4_MAPPING;

// Very simple inet_pton(3) equivalent.
exports.inet_pton = function(str) {
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
};
