/**
 * Working with messages.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Message_types}
 * @see {@link https://bitmessage.org/wiki/Protocol_specification_v3#Message_types}
 * @see {@link https://bitmessage.org/Bitmessage%20Technical%20Paper.pdf}
 * @module bitmessage/messages
 */

"use strict";

var assert = require("./util").assert;
var structs = require("./structs");
var UserAgent = require("./user-agent");
var util = require("./util");

/**
 * `version` message.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#version}
 * @namespace
 */
exports.version = {
  /** Random nonce used to detect connections to self. */
  NONCE: new Buffer("20bde0a3355dad78", "hex"),

  /**
   * Decode `version` payload.
   * NOTE: `nonce` is copied.
   * @param {Buffer} buf - `version` payload
   * @return {Object} Decoded `version` structure.
   */
  decode: function(buf) {
    // 4 + 8 + 8 + 26 + 26 + 8 + (1+) + (1+)
    assert(buf.length >= 82, "Buffer is too small");
    var protoVersion = buf.readUInt32BE(0, true);
    var services = structs.serviceFeatures.decode(buf.slice(4, 12));
    var time = util.readTime64BE(buf, 12);
    var short = {short: true};
    var addrRecv = structs.net_addr.decode(buf.slice(20, 46), short);
    var addrFrom = structs.net_addr.decode(buf.slice(46, 72), short);
    var nonce = new Buffer(8);
    buf.copy(nonce, 0, 72, 80);
    var decodedUa = UserAgent.decode(buf.slice(80));
    var decodedStreamNumbers = structs.var_int_list.decode(decodedUa.rest);
    return {
      version: protoVersion,
      services: services,
      time: time,
      remoteHost: addrRecv.host,
      remotePort: addrRecv.port,
      port: addrFrom.port,
      nonce: nonce,
      software: decodedUa.software,
      streamNumbers: decodedStreamNumbers.list,
      // NOTE(Kagami): Real data length. It may be some gap between end
      // of stream numbers list and end of payload:
      //     [payload..............[stream numbers]xxxx]
      // We are currently ignoring that.
      length: 80 + decodedUa.length + decodedStreamNumbers.length,
    };
  },

  /**
   * Encode `version` payload.
   * @param {Object} opts - Version options
   * @return {Buffer} Encoded `version` payload.
   */
  encode: function(opts) {
    // Deal with default options.
    var services = opts.services || [structs.serviceFeatures.NODE_NETWORK];
    var time = opts.time || new Date();
    var nonce = opts.nonce || exports.version.NONCE;
    assert(nonce.length === 8, "Bad nonce");
    var software = opts.software || UserAgent.SELF;
    var streamNumbers = opts.streamNumbers || [1];
    // Start encoding.
    var protoVersion = new Buffer(4);
    protoVersion.writeUInt32BE(require("./").PROTOCOL_VERSION, 0);
    var addrRecv = structs.net_addr.encode({
      services: services,
      host: opts.remoteHost,
      port: opts.remotePort,
      short: true,
    });
    var addrFrom = structs.net_addr.encode({
      services: services,
      host: "127.0.0.1",
      port: opts.port,
      short: true,
    });
    return Buffer.concat([
      protoVersion,
      structs.serviceFeatures.encode(services),
      util.writeTime64BE(null, time),
      addrRecv,
      addrFrom,
      nonce,
      UserAgent.encode(software),
      structs.var_int_list.encode(streamNumbers),
    ]);
  },
};

/**
 * `addr` message. Provide information on known nodes of the network.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#addr}
 * @namespace
 */
exports.addr = {
  /**
   * Decode `addr` payload.
   * @param {Buffer} buf - `addr` payload
   * @return {Object} Decoded `addr` structure.
   */
  decode: function(buf) {
    var decoded = structs.var_int.decode(buf);
    var listLength = decoded.value;
    assert(listLength <= 1000, "Too many address entires");
    var length = decoded.length + listLength * 38;
    assert(buf.length >= length, "Buffer is too small");
    var rest = decoded.rest;
    var addrs = new Array(listLength);
    for (var i = 0; i < listLength; i++) {
      addrs[i] = structs.net_addr.decode(rest.slice(i*38, (i+1)*38));
    }
    return {
      addrs: addrs,
      // Real data length.
      length: length,
    };
  },

  /**
   * Encode `addr` payload.
   * @param {Object[]} addrs - Network addresses
   * @return {Buffer} Encoded `addr` payload.
   */
  encode: function(addrs) {
    assert(addrs.length <= 1000, "Too many address entires");
    var addrsBuf = Buffer.concat(addrs.map(structs.net_addr.encode));
    return Buffer.concat([structs.var_int.encode(addrs.length), addrsBuf]);
  },
};

/**
 * `inv` message. Allows a node to advertise its knowledge of one or
 * more objects.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#inv}
 * @namespace
 * @static
 */
var inv = exports.inv = {
  /**
   * Decode `inv` payload.
   * @param {Buffer} buf - `inv` payload
   * @return {Object} Decoded `inv` structure.
   */
  decode: function(buf) {
    var decoded = structs.var_int.decode(buf);
    var listLength = decoded.value;
    assert(listLength <= 50000, "Too many inventory entires");
    var length = decoded.length + listLength * 32;
    assert(buf.length >= length, "Buffer is too small");
    var rest = decoded.rest;
    var inventory = new Array(listLength);
    for (var i = 0; i < listLength; i++) {
      inventory[i] = rest.slice(i*32, (i+1)*32);
    }
    return {
      inventory: inventory,
      // Real data length.
      length: length,
    };
  },

  /**
   * Encode `inv` payload.
   * @param {Buffer[]} inventory - Inventory vector list (encoded)
   * @return {Buffer} Encoded `inv` payload.
   */
  encode: function(inventory) {
    assert(inventory.length <= 50000, "Too many inventory entires");
    var invBuf = Buffer.concat(inventory);
    return Buffer.concat([structs.var_int.encode(inventory.length), invBuf]);
  },
};

/**
 * `getdata` message. `getdata` is used in response to an `inv` message
 * to retrieve the content of a specific object after filtering known
 * elements.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#getdata}
 * @namespace
 */
exports.getdata = inv;

/**
 * `error` message.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification_v3#error}
 * @namespace
 */
var error = exports.error = {
  /**
   * Just a warning.
   */
  WARNING: 0,

  /**
   * It's an error, something was going wrong (e.g. an object got lost).
   */
  ERROR: 1,

  /**
   * It's a fatal error. The node will drop the line for that error and
   * maybe ban you for some time.
   */
  FATAL: 2,

  /**
   * Decode `error` payload.
   * @param {Buffer} buf - `error` payload
   * @return {Object} Decoded `error` structure.
   */
  decode: function(buf) {
    assert(buf.length >= 4, "Buffer is too small");
    var decodedFatal = structs.var_int.decode(buf);
    var decodedBanTime = structs.var_int.decode(decodedFatal.rest);
    var decodedVector = structs.var_str.decode(decodedBanTime.rest);
    var decodedErrorText = structs.var_str.decode(decodedVector.rest);
    var length = (
      decodedFatal.length +
      decodedBanTime.length +
      decodedVector.length +
      decodedErrorText.length
    );
    return {
      fatal: decodedFatal.value,
      banTime: decodedBanTime.value,
      vector: decodedVector.str,
      errorText: decodedErrorText.str,
      // Real data length.
      length: length,
    };
  },

  /**
   * Encode `error` payload.
   * @param {Object} opts - Error options
   * @return {Buffer} Encoded `error` payload.
   */
  encode: function(opts) {
    var fatal = opts.fatal || error.WARNING;
    var banTime = opts.banTime || 0;
    var vector = opts.vector || "";
    var errorText = opts.errorText || "";
    return Buffer.concat([
      structs.var_int.encode(fatal),
      structs.var_int.encode(banTime),
      structs.var_str.encode(vector),
      structs.var_str.encode(errorText),
    ]);
  },
};

/**
 * `object` message. An `object` is a message which is shared throughout
 * a stream. It is the only message which propagates; all others are
 * only between two nodes.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#object}
 * @namespace
 */
exports.object = {
  /**
   * Decode `object` payload.
   * NOTE: `nonce` and `payload` are copied.
   * @param {Buffer} buf - `object` payload
   * @return {Object} Decoded `object` structure.
   */
  decode: function(buf) {
    // 8 + 8 + 4 + (1+) + (1+)
    assert(buf.length >= 22, "Buffer is too small");
    var nonce = new Buffer(8);
    buf.copy(nonce, 0, 0, 8);
    var expiresTime = util.readTimestamp64BE(buf.slice(8, 16));
    var ttl = expiresTime - util.tnow();
    assert(ttl >= -3600, "Object expired more than a hour ago");
    assert(ttl <= 2430000, "expiresTime is too far in the future");
    var type = buf.readUInt32BE(16);
    var decodedVersion = structs.var_int.decode(buf.slice(20));
    var decodedStream = structs.var_int.decode(decodedVersion.rest);
    var payload = new Buffer(decodedStream.rest.length);
    decodedStream.rest.copy(payload);
    return {
      nonce: nonce,
      ttl: ttl,
      type: type,
      version: decodedVersion.value,
      stream: decodedStream.value,
      payload: payload,
    };
  },

  /**
   * Encode `object` payload.
   * @param {Object} opts - Object options
   * @return {Buffer} Encoded `object` payload.
   */
  encode: function(opts) {
    assert(opts.nonce.length === 8, "Bad nonce");
    assert(opts.ttl > 0, "Bad TTL");
    assert(opts.ttl <= 2430000, "TTL may not be larger than 28 days + 3 hours");
    var expiresTime = util.tnow() + opts.ttl;
    var type = new Buffer(4);
    type.writeUInt32BE(opts.type, 0);
    var stream = opts.stream || 1;
    return Buffer.concat([
      opts.nonce,
      util.writeUInt64BE(null, expiresTime),
      type,
      structs.var_int.encode(opts.version),
      structs.var_int.encode(stream),
      opts.payload,
    ]);
  },
};
