/**
 * Browser Bitmessage crypto implementation.
 *
 * Documentation: <http://www.w3.org/TR/WebCryptoAPI/>
 * Browsers support: <http://caniuse.com/#feat=cryptography>
 * Blink implementation details: <https://sites.google.com/a/chromium.org/dev/blink/webcrypto>
 */

"use strict";

var assert = require("assert");
require("es6-promise").polyfill();
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
  // XXX(Kagami): No support in browsers via Web Crypto API currently,
  // so use module.
  return Promise.resolve(ripemd160(buf));
};
