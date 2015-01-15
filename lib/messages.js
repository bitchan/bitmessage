/**
 * Working with messages.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Message_types}
 * @module bitmessage/messages
 */

"use strict";

var assert = require("./util").assert;
var structs = require("./structs");
var UserAgent = require("./user-agent");
var util = require("./util");

/**
 * Version message.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#version}
 * @namespace
 */
exports.version = {
  /** Random nonce used to detect connections to self. */
  NONCE: new Buffer("20bde0a3355dad78", "hex"),

  /**
   * Decode version payload.
   * NOTE: `nonce` is copied.
   * @param {Buffer} buf - Buffer that starts with encoded version
   * payload
   * @return {Object} Decoded version structure.
   */
  decode: function(payload) {
    // 4 + 8 + 8 + 26 + 26 + 8 + (1+) + (1+)
    assert(payload.length >= 82, "Message payload is too small");
    var protoVersion = payload.readUInt32BE(0, true);
    var services = structs.serviceFeatures.decode(payload.slice(4, 12));
    var time = util.readTime64BE(payload, 12);
    var short = {short: true};
    var addrRecv = structs.net_addr.decode(payload.slice(20, 46), short);
    var addrFrom = structs.net_addr.decode(payload.slice(46, 72), short);
    var nonce = new Buffer(8);
    payload.copy(nonce, 0, 72, 80);
    var decodedUa = UserAgent.decode(payload.slice(80));
    var decodedStreamNumbers = structs.var_int_list.decode(decodedUa.rest);
    return {
      version: protoVersion,
      services: services,
      time: time,
      remoteHost: addrRecv.host,
      remotePort: addrRecv.port,
      port: addrFrom.port,
      nonce: nonce,
      software: decodedUa.software,
      streamNumbers: decodedStreamNumbers.list,
      // NOTE(Kagami): Real data length. It may be some gap between end
      // of stream numbers list and end of payload:
      //     [payload..............[stream numbers]xxxx]
      // We are currently ignoring that.
      length: 80 + decodedUa.length + decodedStreamNumbers.length,
    };
  },

  /**
   * Encode version payload.
   * @param {Object} opts - Version options
   * @return {Buffer} Encoded version payload.
   */
  encode: function(opts) {
    // Deal with default options.
    var services = opts.services || [structs.serviceFeatures.NODE_NETWORK];
    var time = opts.time || new Date();
    var nonce = opts.nonce || exports.version.NONCE;
    var software = opts.software || UserAgent.SELF;
    var streamNumbers = opts.streamNumbers || [1];
    // Start encoding.
    var protoVersion = new Buffer(4);
    protoVersion.writeUInt32BE(require("./").PROTOCOL_VERSION, 0);
    var addrRecv = structs.net_addr.encode({
      services: services,
      host: opts.remoteHost,
      port: opts.remotePort,
      short: true,
    });
    var addrFrom = structs.net_addr.encode({
      services: services,
      host: "127.0.0.1",
      port: opts.port,
      short: true,
    });
    return Buffer.concat([
      protoVersion,
      structs.serviceFeatures.encode(services),
      util.writeTime64BE(null, time),
      addrRecv,
      addrFrom,
      nonce,
      UserAgent.encode(software),
      structs.var_int_list.encode(streamNumbers),
    ]);
  },
};
