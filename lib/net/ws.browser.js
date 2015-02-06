/**
 * WebSocket transport. Generally needed because browsers can't handle
 * TCP sockets so we proxy messages from clients via WebSocket into TCP
 * data packets.
 */

"use strict";

var inherits = require("inherits");
var assert = require("../_util").assert;
var BaseTransport = require("./base");

/**
 * WebSocket transport constructor.
 * @constructor
 * @static
 */
function Transport() {
  Transport.super_.call(this);
}

inherits(Transport, BaseTransport);

Transport.prototype.connect = function(opts) {
  assert(!this._client, "Already connected");
  this._client = new WebSocket(opts);
};

module.exports = Transport;
