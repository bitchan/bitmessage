/**
 * Browser version of the crypto for Bitmessage JS implementation.
 * @module bitmessage/lib/crypto.browser
 */

"use strict";

exports.sha512 = function(buf) {
  return window.crypto.subtle.digest({name: "SHA-512"}, buf).then(function(arr) {
    return new Buffer(new Uint8Array(arr));
  });
};
