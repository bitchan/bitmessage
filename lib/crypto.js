/**
 * Isomorphic Bitmessage crypto module. Reexport platform-specific
 * functions and also export some common routines.
 * @module bitmessage/crypto
 */

"use strict";

var cryptoPlatform = require("./crypto-platform");

Object.keys(cryptoPlatform).forEach(function(key) {
  exports[key] = cryptoPlatform[key];
});
