/**
 * Browser Bitmessage crypto implementation.
 * Documentation: <http://www.w3.org/TR/WebCryptoAPI/>
 * Browsers support: <http://caniuse.com/#feat=cryptography>
 * Blink implementation details: <https://sites.google.com/a/chromium.org/dev/blink/webcrypto>
 */

"use strict";

require("es6-promise").polyfill();
var assert = require("assert");
var ripemd160 = require("ripemd160");

// Support `webkit` prefix for Safari (not tested yet).
// TODO(Kagami): Try to support IE11.
var subtle = window.crypto.subtle || window.crypto.webkitSubtle;
assert(subtle, "WebCryptoAPI is not supported");

exports.sha512 = function(buf) {
  return subtle.digest({name: "SHA-512"}, buf).then(function(arr) {
    return new Buffer(new Uint8Array(arr));
  });
};

exports.sha256 = function(buf) {
  return subtle.digest({name: "SHA-256"}, buf).then(function(arr) {
    return new Buffer(new Uint8Array(arr));
  });
};

exports.ripemd160 = function(buf) {
  // XXX(Kagami): RIPEMD is not defined in WebCryptoAPI so we provide it
  // using pure JS third-party implementation.
  return Promise.resolve(ripemd160(buf));
};

exports.randomBytes = function(size) {
  var arr = new Uint8Array(size);
  window.crypto.getRandomValues(arr);
  return new Buffer(arr);
};
