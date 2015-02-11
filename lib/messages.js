/**
 * Working with messages.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Message_types}
 * @see {@link https://bitmessage.org/wiki/Protocol_specification_v3#Message_types}
 * @see {@link https://bitmessage.org/Bitmessage%20Technical%20Paper.pdf}
 * @module bitmessage/messages
 */
// TODO(Kagami): Document object-like params.

"use strict";

var objectAssign = Object.assign || require("object-assign");
var bufferEqual = require("buffer-equal");
var assert = require("./_util").assert;
var structs = require("./structs");
var bmcrypto = require("./crypto");
var UserAgent = require("./user-agent");
var util = require("./_util");

var message = structs.message;
var ServicesBitfield = structs.ServicesBitfield;

/**
 * Try to get command of the given encoded message.
 * Note that this function doesn't do any validation because it is
 * already provided by
 * [message.decode]{@link module:bitmessage/structs.message.decode}
 * routine.
 * @param {Buffer} buf - Buffer that starts with encoded message
 * @return {?string} Message's command if any.
 */
exports.getCommand = function(buf) {
  if (buf.length < 16) {
    return;
  }
  var command = buf.slice(4, 16);
  var firstNonNull = 0;
  for (var i = 11; i >=0; i--) {
    if (command[i] !== 0) {
      firstNonNull = i + 1;
      break;
    }
  }
  return command.slice(0, firstNonNull).toString("ascii");
};

// Random nonce used to detect connections to self.
var randomNonce = bmcrypto.randomBytes(8);

/**
 * `version` message.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#version}
 * @namespace
 * @static
 */
// TODO(Kagami): User agent and stream numbers size limits per
// <https://github.com/Bitmessage/PyBitmessage/issues/767>.
var version = exports.version = {
  /**
   * Decode `version` message.  
   * NOTE: `nonce` is copied.
   * @param {Buffer} buf - Message
   * @return {Object} Decoded `version` structure.
   */
  decode: function(buf) {
    var decoded = message.decode(buf);
    assert(decoded.command === "version", "Bad command");
    return version.decodePayload(decoded.payload);
  },

  /**
   * Decode `version` message payload.  
   * NOTE: `nonce` is copied.
   * @param {Buffer} buf - Message payload
   * @return {Object} Decoded `version` structure.
   */
  decodePayload: function(buf) {
    // 4 + 8 + 8 + 26 + 26 + 8 + (1+) + (1+)
    assert(buf.length >= 82, "Buffer is too small");
    var protoVersion = buf.readUInt32BE(0, true);
    var services = ServicesBitfield(buf.slice(4, 12), {copy: true});
    var time = util.readTime64BE(buf, 12);
    var short = {short: true};
    var addrRecv = structs.net_addr.decode(buf.slice(20, 46), short);
    var addrFrom = structs.net_addr.decode(buf.slice(46, 72), short);
    var nonce = new Buffer(8);
    buf.copy(nonce, 0, 72, 80);
    assert(!bufferEqual(nonce, randomNonce), "Connection to self");
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
      userAgent: decodedUa.str,
      streamNumbers: decodedStreamNumbers.list,
      // NOTE(Kagami): Real data length. It may be some gap between end
      // of stream numbers list and end of payload:
      //     [payload..............[stream numbers]xxxx]
      // We are currently ignoring that.
      length: 80 + decodedUa.length + decodedStreamNumbers.length,
    };
  },

  /**
   * Encode `version` message.
   * @param {Object} opts - Version options
   * @return {Buffer} Encoded message.
   */
  encode: function(opts) {
    var payload = version.encodePayload(opts);
    return message.encode("version", payload);
  },

  /**
   * Encode `version` message payload.
   * @param {Object} opts - Version options
   * @return {Buffer} Encoded payload.
   */
  encodePayload: function(opts) {
    // Deal with default options.
    var services = opts.services ||
                   ServicesBitfield().set(ServicesBitfield.NODE_NETWORK);
    var time = opts.time || new Date();
    var nonce = opts.nonce || randomNonce;
    assert(nonce.length === 8, "Bad nonce");
    var port = opts.port || 8444;
    var userAgent = opts.userAgent || UserAgent.SELF;
    var streamNumbers = opts.streamNumbers || [1];
    // Start encoding.
    var protoVersion = new Buffer(4);
    protoVersion.writeUInt32BE(util.PROTOCOL_VERSION, 0);
    var addrRecv = structs.net_addr.encode({
      services: services,
      host: opts.remoteHost,
      port: opts.remotePort,
      short: true,
    });
    var addrFrom = structs.net_addr.encode({
      services: services,
      host: "127.0.0.1",
      port: port,
      short: true,
    });
    return Buffer.concat([
      protoVersion,
      services.buffer,
      util.writeTime64BE(null, time),
      addrRecv,
      addrFrom,
      nonce,
      UserAgent.encode(userAgent),
      structs.var_int_list.encode(streamNumbers),
    ]);
  },
};

/**
 * `addr` message. Provide information on known nodes of the network.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#addr}
 * @namespace
 * @static
 */
var addr = exports.addr = {
  /**
   * Decode `addr` message.
   * @param {Buffer} buf - Message
   * @return {Object} Decoded `addr` structure.
   */
  decode: function(buf) {
    var decoded = message.decode(buf);
    assert(decoded.command === "addr", "Bad command");
    return addr.decodePayload(decoded.payload);
  },

  /**
   * Decode `addr` message payload.
   * @param {Buffer} buf - Message payload
   * @return {Object} Decoded `addr` structure.
   */
  decodePayload: function(buf) {
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
   * Encode `addr` message.
   * @param {Object[]} addrs - Network addresses
   * @return {Buffer} Encoded message.
   */
  encode: function(addrs) {
    var payload = addr.encodePayload(addrs);
    return message.encode("addr", payload);
  },

  /**
   * Encode `addr` message payload.
   * @param {Object[]} addrs - Network addresses
   * @return {Buffer} Encoded payload.
   */
  encodePayload: function(addrs) {
    assert(addrs.length <= 1000, "Too many address entires");
    var addrBufs = addrs.map(structs.net_addr.encode);
    var bufs = [structs.var_int.encode(addrs.length)].concat(addrBufs);
    return Buffer.concat(bufs);
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
   * Decode `inv` message.
   * @param {Buffer} buf - Message
   * @return {Object} Decoded `inv` structure.
   */
  decode: function(buf) {
    var decoded = message.decode(buf);
    assert(decoded.command === "inv", "Bad command");
    return inv.decodePayload(decoded.payload);
  },

  /**
   * Decode `inv` message payload.
   * @param {Buffer} buf - Message payload
   * @return {Object} Decoded `inv` structure.
   */
  decodePayload: function(buf) {
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
   * Encode `inv` message.
   * @param {Buffer[]} inventory - Inventory vector list
   * @return {Buffer} Encoded message.
   */
  encode: function(inventory) {
    var payload = inv.encodePayload(inventory);
    return message.encode("inv", payload);
  },

  /**
   * Encode `inv` message payload.
   * @param {Buffer[]} inventory - Inventory vector list
   * @return {Buffer} Encoded payload.
   */
  encodePayload: function(inventory) {
    assert(inventory.length <= 50000, "Too many inventory entires");
    // TODO(Kagami): Validate vectors length.
    var bufs = [structs.var_int.encode(inventory.length)].concat(inventory);
    return Buffer.concat(bufs);
  },
};

/**
 * `getdata` message. `getdata` is used in response to an
 * [inv]{@link module:bitmessage/messages.inv} message to retrieve the
 * content of a specific object after filtering known elements.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#getdata}
 * @namespace
 */
exports.getdata = objectAssign({}, inv, {
  /**
   * Decode `getdata` message.
   * @param {Buffer} buf - Message
   * @return {Object} Decoded `getdata` structure.
   * @memberof module:bitmessage/messages.getdata
   */
  decode: function(buf) {
    var decoded = message.decode(buf);
    assert(decoded.command === "getdata", "Bad command");
    return inv.decodePayload(decoded.payload);
  },
  /**
   * Encode `getdata` message.
   * @param {Buffer[]} inventory - Inventory vector list
   * @return {Buffer} Encoded message.
   * @memberof module:bitmessage/messages.getdata
   */
  encode: function(inventory) {
    var payload = inv.encodePayload(inventory);
    return message.encode("getdata", payload);
  },
  /**
   * Decode `getdata` message payload.
   * @param {Buffer} buf - Message payload
   * @return {Object} Decoded `inv` structure.
   * @function decodePayload
   * @memberof module:bitmessage/messages.getdata
   */
  /**
   * Encode `getdata` message payload.
   * @param {Buffer[]} inventory - Inventory vector list
   * @return {Buffer} Encoded payload.
   * @function encodePayload
   * @memberof module:bitmessage/messages.getdata
   */
});

/**
 * `error` message.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification_v3#error}
 * @namespace
 * @static
 */
var error = exports.error = {
  /**
   * Just a warning.
   * @constant {number}
   */
  WARNING: 0,

  /**
   * It's an error, something was going wrong (e.g. an object got lost).
   * @constant {number}
   */
  ERROR: 1,

  /**
   * It's a fatal error. The node will drop the line for that error and
   * maybe ban you for some time.
   * @constant {number}
   */
  FATAL: 2,

  /**
   * Decode `error` message.
   * @param {Buffer} buf - Message
   * @return {Object} Decoded `error` structure.
   */
  decode: function(buf) {
    var decoded = message.decode(buf);
    assert(decoded.command === "error", "Bad command");
    return error.decodePayload(decoded.payload);
  },

  /**
   * Decode `error` message payload.
   * @param {Buffer} buf - Message payload
   * @return {Object} Decoded `error` structure.
   */
  decodePayload: function(buf) {
    assert(buf.length >= 4, "Buffer is too small");
    var decodedFatal = structs.var_int.decode(buf);
    var decodedBanTime = structs.var_int.decode(decodedFatal.rest);

    var decodedVectorLength = structs.var_int.decode(decodedBanTime.rest);
    // NOTE(Kagami): Inventory vector should be only 32-byte in size but
    // currently we don't ensure it.
    var vectorLength = decodedVectorLength.value;
    var rest = decodedVectorLength.rest;
    assert(rest.length >= vectorLength, "Buffer is too small");
    var vector = new Buffer(vectorLength);
    rest.copy(vector);
    rest = rest.slice(vectorLength);

    var decodedErrorText = structs.var_str.decode(rest);
    var length = (
      decodedFatal.length +
      decodedBanTime.length +
      decodedVectorLength.length + vectorLength +
      decodedErrorText.length
    );
    return {
      fatal: decodedFatal.value,
      banTime: decodedBanTime.value,
      vector: vector,
      errorText: decodedErrorText.str,
      // Real data length.
      length: length,
    };
  },

  /**
   * Encode `error` message.
   * @param {Object} opts - Error options
   * @return {Buffer} Encoded message.
   */
  encode: function(opts) {
    var payload = error.encodePayload(opts);
    return message.encode("error", payload);
  },

  /**
   * Encode `error` message payload.
   * @param {Object} opts - Error options
   * @return {Buffer} Encoded payload.
   */
  encodePayload: function(opts) {
    var fatal = opts.fatal || error.WARNING;
    var banTime = opts.banTime || 0;
    // TODO(Kagami): Validate vector length.
    var vector = opts.vector || new Buffer(0);
    return Buffer.concat([
      structs.var_int.encode(fatal),
      structs.var_int.encode(banTime),
      structs.var_int.encode(vector.length),
      vector,
      structs.var_str.encode(opts.errorText),
    ]);
  },
};
