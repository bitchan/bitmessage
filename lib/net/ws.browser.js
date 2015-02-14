/**
 * WebSocket transport. Used in browser in client-mode only. Server
 * handle incoming messages and wrap them into TCP data packets.
 */

"use strict";

var objectAssign = Object.assign || require("object-assign");
var inherits = require("inherits");
var assert = require("../_util").assert;
var structs = require("../structs");
var messages = require("../messages");
var BaseTransport = require("./base");

function WsTransport(opts) {
  WsTransport.super_.call(this);
  objectAssign(this, opts);
  this.seeds = this.seeds || [];
}

inherits(WsTransport, BaseTransport);

WsTransport.prototype.bootstrap = function() {
  return Promise.resolve([].concat(this.seeds));
};

WsTransport.prototype.connect = function(url, protocols) {
  var self = this;
  assert(!self._client, "Already connected");

  // TODO(Kagami): Handle timeouts!
  var client = self._client = new WebSocket(url, protocols);
  client.binaryType = "arraybuffer";
  var verackSent = false;
  var verackReceived = false;
  var established = false;

  client.onopen = function() {
    self.emit("open");
    self.send(messages.version.encode({
      services: self.services,
      userAgent: self.userAgent,
      streamNumbers: self.streamNumbers,
      // This parameters aren't used by the remote node so we fake them
      // (because we can't resolve domain name in a Browser).
      remoteHost: "127.0.0.1",
      remotePort: 8444,
    }));
  };

  client.onmessage = function(e) {
    var buf = new Buffer(new Uint8Array(e.data));
    var decoded;
    try {
      decoded = structs.message.decode(buf);
    } catch (err) {
      return self.emit("warning", new Error(
        "Message decoding error from " + url + ": " + err
      ));
    }
    self.emit("message", decoded.command, decoded.payload, decoded);
  };

  // High-level message processing.
  self.on("message", function(command) {
    if (!established) {
      // TODO: Process version data.
      // TODO: Disconnect if proto version < 3.
      if (command === "version") {
        if (verackSent) {
          return;
        }
        self.send("verack");
        verackSent = true;
        if (verackReceived) {
          established = true;
          self.emit("established");
        }
      } else if (command === "verack") {
        verackReceived = true;
        if (verackSent) {
          established = true;
          self.emit("established");
        }
      }
    }
  });

  client.onerror = function(err) {
    self.emit("error", err);
  };

  client.onclose = function() {
    self.emit("close");
    delete self._client;
  };
};

WsTransport.prototype.send = function() {
  if (this._client) {
    this._client.send(BaseTransport._getmsg(arguments));
  } else {
    throw new Error("Not connected");
  }
};

WsTransport.prototype.close = function() {
  if (this._client) {
    this._client.close();
  }
};

module.exports = WsTransport;
