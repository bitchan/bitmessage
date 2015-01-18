/**
 * Working with objects.
 * NOTE: All operations with objects in this module are asynchronous and
 * return promises.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#Object_types}
 * @module bitmessage/objects
 */
// TODO(Kagami): Document object-like params.

"use strict";

var objectAssign = Object.assign || require("object-assign");
var assert = require("./util").assert;
var promise = require("./platform").promise;
var object = require("./messages").object;
var Address = require("./address");

/**
 * `getpubkey` object. When a node has the hash of a public key (from an
 * address) but not the public key itself, it must send out a request
 * for the public key.
 * @see {@link https://bitmessage.org/wiki/Protocol_specification#getpubkey}
 * @namespace
 */
exports.getpubkey = {
  /**
   * Decode `getpubkey` object message payload.
   * @param {Buffer} buf - Message payload
   * @return {Promise.<Object>} A promise that contained decoded
   * `getpubkey` object structure when fulfilled.
   */
  decodeAsync: function(buf) {
    return new promise(function(resolve) {
      var decoded = object.decode(buf);
      assert(decoded.type === object.GETPUBKEY, "Wrong object type");
      var payload = decoded.payload;
      delete decoded.payload;
      if (decoded.version < 4) {
        assert(payload.length === 20, "getpubkey ripe is too small");
        // Payload is copied so it's safe to return it right away.
        decoded.ripe = payload;
      } else {
        assert(payload.length === 32, "getpubkey tag is too small");
        // Payload is copied so it's safe to return it right away.
        decoded.tag = payload;
      }
      resolve(decoded);
    });
  },

  /**
   * Encode `getpubkey` object message payload.
   * @param {Object} opts - `getpubkey` object options
   * @return {Promise.<Buffer>} A promise that contained encoded message
   * payload when fulfilled.
   */
  encodeAsync: function(opts) {
    return new promise(function(resolve) {
      opts = objectAssign({}, opts);
      opts.type = object.GETPUBKEY;
      var addr = Address.decode(opts.to);
      opts.version = addr.version;
      opts.stream = addr.stream;
      opts.payload = addr.version < 4 ? addr.getRipe() : addr.getTag();
      resolve(object.encode(opts));
    });
  },
};
