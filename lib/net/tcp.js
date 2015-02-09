/**
 * TCP transport. Should be compatible with PyBitmessage. Available only
 * for Node.js.
 * @module bitmessage/net/tcp
 */

"use strict";

var objectAssign = Object.assign || require("object-assign");
var inherits = require("inherits");
var net = require("net");
var dns = require("dns");
var assert = require("../_util").assert;
var PPromise = require("../platform").Promise;
var structs = require("../structs");
var messages = require("../messages");
var BaseTransport = require("./base");

/**
 * TCP transport constructor.
 * @constructor
 * @static
 */
function Transport(opts) {
  Transport.super_.call(this);
  objectAssign(this, opts);
  this.seeds = this.seeds || [];
  this.dnsSeeds = this.dnsSeeds || [];
  this._clients = {};
  if (this._client) {
    this._setupClient();
  }
}

inherits(Transport, BaseTransport);

// Unmap IPv4-mapped IPv6 address.
function unmap(addr) {
  if (addr.slice(0, 7) === "::ffff:") {
    return addr.slice(7);
  } else {
    return addr;
  }
}

Transport.prototype.sendVersion = function() {
  return this.send(messages.version.encode({
    services: this.services,
    userAgent: this.userAgent,
    streamNumbers: this.streamNumbers,
    port: this.port,
    remoteHost: this._client.remoteAddress,
    remotePort: this._client.remotePort,
  }));
};

Transport.prototype._setupClient = function() {
  var self = this;
  var client = self._client;
  var cache = Buffer(0);
  var decoded;
  var verackSent = false;
  var verackReceived = false;
  var established = false;

  // Set default transport timeout per spec.
  // TODO(Kagami): We may also want to close connection if it wasn't
  // established within minute.
  client.setTimeout(20000);

  client.on("connect", function() {
    self.emit("open");
    // NOTE(Kagami): This handler shouldn't be called at all for
    // accepted sockets but let's be sure.
    if (!self._accepted) {
      self.sendVersion();
    }
  });

  client.on("data", function(data) {
    // TODO(Kagami): We may want to preallocate 1.6M buffer for each
    // client instead (max size of the message) to not constantly
    // allocate new buffers. Though this may lead to another issues: too
    // many memory per client.
    cache = Buffer.concat([cache, data]);
    while (true) {
      decoded = structs.message.tryDecode(cache);
      if (!decoded) {
        break;
      }
      cache = decoded.rest;
      if (decoded.message) {
        self.emit(
          "message",
          decoded.message.command,
          decoded.message.payload,
          decoded.message);
      } else if (decoded.error) {
        // TODO(Kagami): Wrap it in custom error class?
        // TODO(Kagami): Send `error` message and ban node for some time
        // if there were too many errors?
        self.emit("warning", new Error(
          "Message decoding error from " +
          unmap(client.remoteAddress) + ":" + client.remotePort,
          ": " +
          decoded.error
        ));
      }
    }
  });

  // High-level message processing.
  self.on("message", function(command) {
    if (!established) {
      // TODO: Process version data.
      if (command === "version") {
        if (verackSent) {
          return;
        }
        self.send("verack");
        verackSent = true;
        if (self._accepted) {
          self.sendVersion();
        }
        if (verackReceived) {
          self.emit("established");
        }
      } else if (command === "verack") {
        verackReceived = true;
        if (verackSent) {
          self.emit("established");
        }
      }
    }
  });

  self.on("established", function() {
    established = true;
    // Raise timeout up to 10 minutes per spec.
    // TODO(Kagami): Send pong messages every 5 minutes as PyBitmessage.
    client.setTimeout(600000);
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
    verackSent = false;
    verackReceived = false;
    established = false;
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
    // Flatten array of arrays.
    dnsNodes = Array.prototype.concat.apply([], dnsNodes);
    // Add hardcoded nodes to the end of list because DNS nodes should
    // be more up-to-date.
    return dnsNodes.concat(hardcodedNodes);
  });
};

Transport.prototype.connect = function() {
  assert(!this._client, "Already connected");
  assert(!this._server, "Already listening");

  this._client = net.connect.apply(null, arguments);
  this._setupClient();
};

Transport.prototype.listen = function() {
  assert(!this._client, "Already connected");
  assert(!this._server, "Already listening");

  var self = this;
  var server = self._server = net.createServer();
  server.listen.apply(server, arguments);

  // TODO(Kagami): We may want to specify some limits for number of
  // connected users.
  server.on("connection", function(client) {
    var addr = client.remoteAddress;
    var port = client.remotePort;
    if (self._clients[addr]) {
      // NOTE(Kagami): Doesn't allow more than one connection per IP.
      // This may obstruct people behind NAT but we copy PyBitmessage's
      // behavior here.
      client.end();
      self.emit("warning", new Error(
        addr + " was tried to create second connection"
      ));
      return;
    }
    self._clients[addr] = client;
    client.on("close", function() {
      delete self._clients[addr];
    });
    var transport = new self.constructor(objectAssign({}, self, {
      _client: client,
      _accepted: true,
    }));
    self.emit("connection", transport, unmap(addr), port);
    // Emit "open" manually because "connect" won't be emitted.
    transport.emit("open");
  });

  server.on("error", function(err) {
    self.emit("error", err);
  });

  server.on("close", function() {
    self.emit("close");
    delete self._server;
  });
};

function getmsg(args) {
  if (typeof args[0] === "string") {
    return structs.message.encode(args[0], args[1]);
  } else {
    return args[0];
  }
}

Transport.prototype.send = function() {
  if (this._client) {
    this._client.write(getmsg(arguments));
  } else {
    throw new Error("Not connected");
  }
};

Transport.prototype.broadcast = function() {
  var data = getmsg(arguments);
  if (this._server) {
    Object.keys(this._clients).forEach(function(ip) {
      this._clients[ip].write(data);
    }, this);
  } else {
    throw new Error("Not listening");
  }
};

Transport.prototype.close = function() {
  if (this._client) {
    this._client.end();
  } else if (this._server) {
    Object.keys(this._clients).forEach(function(ip) {
      this._clients[ip].end();
    }, this);
    this._server.close();
  }
};

module.exports = Transport;
