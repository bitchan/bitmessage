/**
 * Browser version of the crypto for Bitmessage JS implementation.
 *
 * Documentation: <http://www.w3.org/TR/WebCryptoAPI/>
 * Browsers support: <http://caniuse.com/#feat=cryptography>
 * Blink implementation details: <https://sites.google.com/a/chromium.org/dev/blink/webcrypto>
 *
 * @module bitmessage/crypto.browser
 */
// FIXME(Kagami): Support webkit subtle prefix!
// TODO(Kagami): Try to support IE11.

"use strict";

require("es6-promise").polyfill();
var ripemd160 = require("ripemd160");

exports.sha512 = function(buf) {
  return window.crypto.subtle.digest({name: "SHA-512"}, buf).then(function(arr) {
    return new Buffer(new Uint8Array(arr));
  });
};

exports.ripemd160 = function(buf) {
  // XXX(Kagami): No support in browsers via Web Crypto API currently,
  // so use module.
  return Promise.resolve(ripemd160(buf));
};
