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
var PPromise = require("../platform").Promise;
var structs = require("../structs");

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

// Static private helpers.

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

module.exports = BaseTransport;
