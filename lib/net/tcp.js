/**
 * TCP transport. Should be compatible with PyBitmessage. Available only
 * for Node.js.
 * @module bitmessage/net/tcp
 */

"use strict";

var inherits = require("inherits");
var net = require("net");
var dns = require("dns");
var assert = require("../_util").assert;
var PPromise = require("../platform").Promise;
var BaseTransport = require("./base");

var sockIdCounter = 0;

/**
 * TCP transport constructor.
 * @constructor
 * @static
 */
function Transport(opts) {
  Transport.super_.call(this);
  opts = opts || {};
  this.seeds = opts.seeds || [];
  this.dnsSeeds = opts.dnsSeeds || [];
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

function resolveDnsSeed(seed) {
  var host = seed[0];
  var port = seed[1];
  var nodes = [];
  // NOTE(Kagami):
  // 1) Node's `getaddrinfo` (`dns.lookup`) returns only one address so
  // we can't use it.
  // 2) Node's `dig host any` (`dns.resolve`) doesn't return type of the
  // record! So we resolve twice for A and AAAA.
  // 3) We ignore any errors here, promise's result is always a list.
  return new PPromise(function(resolve) {
    dns.resolve4(host, function(err, nodes4) {
      if (!err) {
        nodes4.forEach(function(n) {
          nodes.push([n, port]);
        });
      }
      dns.resolve6(host, function(err, nodes6) {
        if (!err) {
          nodes6.forEach(function(n) {
            nodes.push([n, port]);
          });
        }
        resolve(nodes);
      });
    });
  });
}

Transport.prototype.bootstrap = function() {
  var promises = this.dnsSeeds.map(resolveDnsSeed);
  var hardcodedNodes = this.seeds;
  // FIXME(Kagami): Filter incorrect/private IP range nodes?
  // See also: <https://github.com/Bitmessage/PyBitmessage/issues/768>.
  return PPromise.all(promises).then(function(dnsNodes) {
    // Add hardcoded nodes to the end of list because DNS nodes should
    // be more up-to-date.
    // Flatten array of array of arrays.
    dnsNodes = Array.prototype.concat.apply([], dnsNodes);
    return dnsNodes.concat(hardcodedNodes);
  });
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
      seeds: self.seeds,
      dnsSeeds: self.dnsSeeds,
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

module.exports = Transport;
