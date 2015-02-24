/**
 * Networking base module. Defines base transport interface, useful for
 * implementing new transports. End-users should import some transport
 * instead in order to connect/accept connections to/from other nodes.  
 * **NOTE**: `BaseTransport` is exported as a module.
 * @example var BaseTransport = require("bitmessage/lib/net/base");
 * @module bitmessage/net/base
 */
// TODO(Kagami): Write some sort of tutorial.

"use strict";

var inherits = require("inherits");
var EventEmitter = require("events").EventEmitter;
var util = require("../_util");
var PPromise = require("../platform").Promise;
var structs = require("../structs");
var messages = require("../messages");

var ServicesBitfield = structs.ServicesBitfield;

/**
 * Base transport class. Allows to use single class for both client and
 * server modes (as separate instances).
 * @constructor
 * @static
 */
function BaseTransport() {
  BaseTransport.super_.call(this);
}

inherits(BaseTransport, EventEmitter);

/**
 * Do the transport-specific bootstrap process and return promise that
 * contains discovered nodes when fulfilled (both modes).  
 * NOTE: Do not use nodes received by this method in `addr` messages!
 * This is meaningless.
 * @return {Promise.<Array>}
 * @abstract
 */
BaseTransport.prototype.bootstrap = function() {
  return PPromise.reject(new Error("Not implemented"));
};

/**
 * Connect to the transport-specific address. Enters client mode. Should
 * emit `open` event after successful connect and `established` event
 * after `verack` messages exchange.
 * @abstract
 */
BaseTransport.prototype.connect = function() {
  throw new Error("Not implemented");
};

/**
 * Listen for the transport-specific incoming connections. Enters server
 * mode. Should emit `connection` event with a transport instance for
 * each new connection.
 * @abstract
 */
BaseTransport.prototype.listen = function() {
  throw new Error("Not implemented");
};

/**
 * Send [message]{@link module:bitmessage/structs.message} over the
 * wire (client mode only).
 * @param {(Buffer|string)} msg - Encoded message or command string
 * @param {Buffer=} payload - Message payload (used if the first
 * argument is a string)
 * @abstract
 */
BaseTransport.prototype.send = function() {
  throw new Error("Not implemented");
};

/**
 * Send [message]{@link module:bitmessage/structs.message} to all
 * connected clients (server mode only).
 * @param {(Buffer|string)} msg - Encoded message or command string
 * @param {Buffer=} payload - Message payload (used if the first
 * argument is a string)
 * @abstract
 */
BaseTransport.prototype.broadcast = function() {
  throw new Error("Not implemented");
};

/**
 * Close connection(s) and/or stop listening (both modes).
 * @abstract
 */
BaseTransport.prototype.close = function() {
  throw new Error("Not implemented");
};

// Private helpers.

// Make a message from variable number of arguments.
BaseTransport._getmsg = function(args) {
  if (typeof args[0] === "string") {
    return structs.message.encode(args[0], args[1]);
  } else {
    return args[0];
  }
};

// Unmap IPv4-mapped IPv6 address.
BaseTransport._unmap = function(addr) {
  if (addr.slice(0, 7) === "::ffff:") {
    return addr.slice(7);
  } else {
    return addr;
  }
};

// Check whether two given arrays intersect.
// NOTE(Kagami): It has O(n*m) complexity in the worst case but:
// * Max length of stream list = 160,000
// * One of the arrays (our streams) should have reasonable length
function intersects(a, b) {
  var alen = a.length;
  var blen = b.length;
  if (!alen || !blen) {
    return false;
  }
  var i, j;
  for (i = 0; i < alen; ++i) {
    for (j = 0; j < blen; ++j) {
      if (a[i] === b[j]) {
        return true;
      }
    }
  }
  return false;
}

// Decode and validate version message.
BaseTransport.prototype._decodeVersion = function(payload, opts) {
  opts = opts || {};
  var version;
  try {
    version = messages.version.decodePayload(payload);
  } catch(err) {
    throw new Error("Version decode error: " + err.message);
  }
  if (version.version < util.PROTOCOL_VERSION) {
    throw new Error("Peer uses old protocol v" + version.version);
  }
  // TODO(Kagami): We may want to send error message describing the time
  // offset problem to this node as PyBitmessage.
  var delta = (version.time.getTime() - new Date().getTime()) / 1000;
  if (delta > 3600) {
    throw new Error("Peer's time is too far in the future: +" + delta + "s");
  }
  if (delta < -3600) {
    throw new Error("Peer's time is too far in the past: " + delta + "s");
  }
  if (!intersects(this.streams, version.streams)) {
    throw new Error(
      "Peer isn't interested in our streams; " +
      "first 10 peer's streams: " + version.streams.slice(0, 10)
    );
  }
  if (opts.network && !version.services.get(ServicesBitfield.NODE_NETWORK)) {
    throw new Error("Not a normal network node: " + version.services);
  }
  if (opts.gateway && !version.services.get(ServicesBitfield.NODE_GATEWAY)) {
    throw new Error("Not a gateway node: " + version.services);
  }
  if (opts.mobile && !version.services.get(ServicesBitfield.NODE_MOBILE)) {
    throw new Error("Not a mobile node: " + version.services);
  }
  return version;
};

module.exports = BaseTransport;
