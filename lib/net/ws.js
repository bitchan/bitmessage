/**
 * WebSocket transport. Generally needed because browsers can't handle
 * TCP sockets so we proxy messages from clients via WebSocket into TCP
 * data packets.
 * @module bitmessage/net/ws
 */

"use strict";

var inherits = require("inherits");
var WebSocket = require("ws");  // jshint ignore:line
var assert = require("../_util").assert;
var BaseTransport = require("./base");

var WebSocketServer = WebSocket.Server;

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

Transport.prototype.listen = function(opts) {
  assert(!this._server, "Already listening");
  this._server = new WebSocketServer(opts);
};

module.exports = Transport;
