/**
 * Node.js version of the crypto for Bitmessage JS implementation.
 * @module bitmessage/crypto
 */

"use strict";

require("es6-promise").polyfill();
var crypto = require("crypto");

exports.sha512 = function(buf) {
  var hash = crypto.createHash("sha512");
  hash.update(buf);
  return Promise.resolve(hash.digest());
};

exports.ripemd160 = function(buf) {
  var hash = crypto.createHash("ripemd160");
  hash.update(buf);
  return Promise.resolve(hash.digest());
};
