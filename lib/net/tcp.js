/**
 * TCP transport. Should be compatible with PyBitmessage. Available only
 * for Node.js.
 * @module bitmessage/net/tcp
 */

"use strict";

var inherits = require("inherits");
var net = require("net");
var assert = require("../_util").assert;
var PPromise = require("../platform").Promise;
var BaseTransport = require("./base").BaseTransport;

var sockIdCounter = 0;

/**
 * TCP transport constructor.
 * @constructor
 * @static
 */
function Transport(opts) {
  Transport.super_.call(this);
  opts = opts || {};
  if (opts.seeds) {
    this.seeds = opts.seeds;
  }
  if (opts.client) {
    this._setupClient(opts.client);
  }
  // To track connected clients in server mode.
  this._clients = {};
}

inherits(Transport, BaseTransport);

Transport.prototype._setupClient = function(client) {
  var self = this;
  self._client = client;

  // Set default transport timeout per spec.
  client.setTimeout(20);

  client.on("connect", function() {
    self.emit("open");
  });

  client.on("data", function() {
  });

  client.on("timeout", function() {
    client.end();
  });

  client.on("error", function(err) {
    self.emit("error", err);
  });

  client.on("close", function() {
    self.emit("close");
    delete self._client;
  });
};

Transport.prototype.bootstrap = function() {
  // TODO(Kagami): Think how to set up DNS/IP nodes. Do we need to
  // hardcode them?
};

Transport.prototype.connect = function() {
  assert(!this._client, "Already connected");
  assert(!this._server, "Already listening");

  var client = net.connect.apply(null, arguments);
  this._setupClient(client);
};

Transport.prototype.listen = function() {
  assert(!this._client, "Already connected");
  assert(!this._server, "Already listening");

  var self = this;
  var server = self._server = net.createServer();
  server.listen.apply(server, arguments);

  server.on("connection", function(sock) {
    sock.id = sockIdCounter++;
    self._clients[sock.id] = sock;
    sock.on("close", function() {
      delete self._clients[sock.id];
    });
    var transport = new self.constructor({
      client: sock,
      seeds: this.seeds,
    });
    self.emit("connection", transport);
  });

  server.on("error", function(err) {
    self.emit("error", err);
  });

  server.on("close", function() {
    self.emit("close");
    delete self._server;
  });
};

Transport.prototype.send = function(data) {
  if (this._client) {
    this._client.write(data);
  } else {
    throw new Error("Not connected");
  }
};

Transport.prototype.broadcast = function(data) {
  if (this._server) {
    Object.keys(this._clients).forEach(function(id) {
      this._clients[id].write(data);
    }, this);
  } else {
    throw new Error("Not listening");
  }
};

Transport.prototype.close = function() {
  if (this._client) {
    this._client.end();
  } else if (this._server) {
    Object.keys(this._clients).forEach(function(id) {
      this._clients[id].end();
    }, this);
    this._server.close();
  }
};

exports.Transport = Transport;
