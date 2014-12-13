/**
 * Node.js version of the crypto for Bitmessage JS implementation.
 * Wrap all crypto functions with promises because WebCryptoAPI uses it
 * throughout.
 * @module bitmessage/lib/crypto
 */

"use strict";

var Promise = require("es6-promise").Promise;  // jshint ignore:line
var crypto = require("crypto");

exports.sha512 = function(buf) {
  var hash = crypto.createHash("sha512");
  hash.update(buf);
  return Promise.resolve(hash.digest());
};
