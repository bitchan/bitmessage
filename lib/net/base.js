/**
 * Networking base module. You should import some transport instead in
 * order to connect/accept connections to/from other nodes.
 * @module bitmessage/net/base
 */
// TODO(Kagami): Write some sort of tutorial.

"use strict";

var inherits = require("inherits");
var EventEmitter = require("events").EventEmitter;
var PPromise = require("../platform").Promise;

/**
 * Network transport base class.
 * @constructor
 * @static
 */
function BaseTransport() {
  BaseTransport.super_.call(this);
}

inherits(BaseTransport, EventEmitter);

/**
 * Seed nodes for this transport. Consist of `[host, port]` pairs.
 * Note that this nodes shouldn't be advertised via `addr` messages.
 * @const {Array.}
 */
BaseTransport.prototype.SEED_NODES = [];

/**
 * Do the transport-specific bootstrap process and return promise that
 * contains discovered nodes when fulfilled.
 * @return {Promise.<Array.>}
 */
BaseTransport.prototype.bootstrap = function() {
  return PPromise.resolve([].concat(this.SEED_NODES));
};

/**
 * Connect to the transport-specific address.
 * Should emit `open` event after successful connect and `established`
 * event after `verack` messages exchange.
 * @abstract
 */
BaseTransport.prototype.connect = function() {
  throw new Error("Not implemented");
};

/**
 * Send [message]{@link module:bitmessage/structs.message} over the
 * wire.
 * @param {Buffer} msg - Encoded message
 * @abstract
 */
BaseTransport.prototype.send = function() {
  throw new Error("Not implemented");
};

/**
 * Close connection.
 * @abstract
 */
BaseTransport.prototype.close = function() {
  throw new Error("Not implemented");
};

/**
 * Listen for the transport-specific incoming connections.
 * Should emit `connection` event with a transport instance for each new
 * connection.
 * @abstract
 */
BaseTransport.prototype.listen = function() {
  throw new Error("Not implemented");
};

exports.BaseTransport = BaseTransport;
