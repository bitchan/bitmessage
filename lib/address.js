/**
 * Working with Bitmessage addresses.
 * @module bitmessage/address
 */

"use strict";

require("es6-promise").polyfill();
require("object.assign").shim();
var assert = require("assert");
var bufferEqual = require("buffer-equal");
var bs58 = require("bs58");
var varint = require("./varint");
var bmcrypto = require("./crypto");

/**
 * Create a new Bitmessage address object.
 * @param {?Object} opts - Address options
 * @constructor
 */
function Address(opts) {
  if (!(this instanceof Address)) {
    return new Address(opts);
  }
  opts = opts || {};
  Object.assign(this, opts);
  this.version = this.version || 4;
  assert(this.version <= 4, "Version too high");
  assert(this.version >= 1, "Version too low");
  this.stream = this.stream || 1;
  if (this.ripe) {
    assertripelen(getripelen(this.ripe), this.version);
  }
}

/**
 * Parse Bitmessage address into address object.
 * @param {String} str - Address string (with or without `BM-` prefix)
 * @return {Promise.<Address,Error>} Decoded address object
 * @static
 */
Address.decode = function(str) {
  str = str.trim();
  if (str.slice(0, 3) === "BM-") {
    str = str.slice(3);
  }

  var bytes;
  try {
    bytes = bs58.decode(str);
  } catch(e) {
    return Promise.reject(e);
  }

  // Checksum validating.
  var data = new Buffer(bytes.slice(0, -4));
  var checksum = new Buffer(bytes.slice(-4));
  return getchecksum(data).then(function(realchecksum) {
    assert(bufferEqual(checksum, realchecksum), "Bad checkum");

    var decoded = varint.decode(data);
    var version = decoded.value;

    data = decoded.rest;
    decoded = varint.decode(data);
    var stream = decoded.value;

    var ripe = decoded.rest;
    var ripelen = ripe.length;
    if (version === 4) {
      assert(ripe[0] !== 0, "Ripe encode error");
    }

    // Prevent extra allocation. God, kill me please for premature
    // optimizations.
    if (ripelen < 20) {
      var zeroes = new Buffer(Array(20 - ripelen));
      ripe = Buffer.concat([zeroes, ripe]);
    }
    return new Address({version: version, stream: stream, ripe: ripe});
  });
};

// Compute the Bitmessage checksum for the given data.
function getchecksum(data) {
  return bmcrypto.sha512(data).then(bmcrypto.sha512).then(function(dhash) {
    return dhash.slice(0, 4);
  });
}

// Get RIPEMD160(SHA512(SIGN_PUBLIC_KEY || ENC_PUBLIC_KEY)).
// Arguments could be either private or public keys. Private keys are
// **always** 32 bytes in length.
function keys2ripe(signKey, encKey) {
  var signPublicKey, encPublicKey;
  if (signKey.length === 32) {
    signPublicKey = bmcrypto.getPublic(signKey);
  } else {
    signPublicKey = signKey;
  }
  if (encKey.length === 32) {
    encPublicKey = bmcrypto.getPublic(encKey);
  } else {
    encPublicKey = encKey;
  }
  var concat = Buffer.concat([signPublicKey, encPublicKey]);
  return bmcrypto.sha512(concat).then(bmcrypto.ripemd160);
}

/**
 * Calculate the Ripe hash of the address.
 * @param {?Object} opts - Options
 * @return {Promise.<Buffer,Error>} Resulting Ripe hash
 */
Address.prototype.getRipe = function(opts) {
  var self = this;
  var ripepromise;
  if (self.ripe) {
    ripepromise = Promise.resolve(self.ripe);
  } else {
    opts = opts || {};
    var signKey = self.signPrivateKey || self.signPublicKey;
    assert(signKey, "No signing key");
    var encKey = self.encPrivateKey || self.encPublicKey;
    assert(encKey, "No encryption key");
    ripepromise = keys2ripe(signKey, encKey);
  }
  return ripepromise.then(function(ripe) {
    var ripelen = getripelen(ripe);
    assertripelen(ripelen, self.version);
    if (opts.short) {
      return ripe.slice(20 - ripelen);
    } else {
      return ripe;
    }
  });
};

// Get truncated Ripe hash length.
function getripelen(ripe) {
  var zeroes = 0;
  for (var i = 0; i < 20, ripe[i] === 0; i++) {
    zeroes++;
  }
  return 20 - zeroes;
}

// Do neccessary checkings of the truncated Ripe hash length depending
// on the address version.
function assertripelen(ripelen, version) {
  switch (version) {
    case 1:
      assert(ripelen === 20, "Bad ripe length");
      break;
    case 2:
    case 3:
      assert(ripelen >= 18, "Ripe too short");
      assert(ripelen <= 20, "Ripe too long");
      break;
    case 4:
      assert(ripelen >= 4, "Ripe too short");
      assert(ripelen <= 20, "Ripe too long");
      break;
    default:
      throw new Error("Bad version");
  }
}

// The same as `assertripelen` but return boolean instead of thrown an
// Error.
function checkripelen(ripelen, version) {
  try {
    assertripelen(ripelen, version);
    return true;
  } catch(e) {
    return false;
  }
}

/**
 * Encode Bitmessage address object into address string.
 * @return {Promise.<string,Error>} Address string
 */
Address.prototype.encode = function() {
  var self = this;
  return self.getRipe({short: true}).then(function(ripe) {
    var data = Buffer.concat([
      varint.encode(self.version),
      varint.encode(self.stream),
      ripe,
    ]);
    return getchecksum(data).then(function(checksum) {
      var addr = Buffer.concat([data, checksum]);
      return "BM-" + bs58.encode(addr);
    });
  });
};

/**
 * Create new Bitmessage address from random encryption and signing
 * private keys.
 * @param {?Object} opts - Address options
 * @return {Promise.<Address,Error>} Generated address object
 * @static
 */
Address.fromRandom = function(opts) {
  opts = opts || {};
  var version = opts.version || 4;
  var ripelen = opts.ripelen || 19;
  try {
    assertripelen(ripelen, version);
  } catch(e) {
    return Promise.reject(e);
  }
  // Should the generated Ripe length be strictly equal to the specified
  // (less-or-equal by default);
  var strictripelen = !!opts.strictripelen;
  var nextTick = typeof setImmediate === "undefined" ?
                 process.nextTick :
                 setImmediate;

  var signPrivateKey = bmcrypto.getPrivate();
  var signPublicKey = bmcrypto.getPublic(signPrivateKey);

  // FIXME(Kagami): This function is rather slow in browsers so
  // generation of ripelen=18 currently is disabled (see `test.js`). It
  // should be heavilty profiled to determine the bottleneck.
  // TODO(Kagami): We may want to run this in the web worker to speedup
  // the search. Currently WebCryptoAPI is not available in Firefox in
  // web workers (see
  // <https://bugzilla.mozilla.org/show_bug.cgi?id=842818>) but is
  // available in Chrome (at least in 39.0+).
  return new Promise(function(resolve, reject) {
    function tryKey() {
      var encPrivateKey = bmcrypto.getPrivate();
      var encPublicKey = bmcrypto.getPublic(encPrivateKey);
      return keys2ripe(signPublicKey, encPublicKey).then(function(ripe) {
        var len = getripelen(ripe);
        if (
          (strictripelen && len === ripelen) ||
          (!strictripelen && len <= ripelen && checkripelen(ripelen, version))
        ) {
          // XXX(Kagami): Do we need to put all these properties or
          // compute them manually via ECMA5 getters/setters instead?
          resolve(new Address(Object.assign({
            signPrivateKey: signPrivateKey,
            signPublicKey: signPublicKey,
            encPrivateKey: encPrivateKey,
            encPublicKey: encPublicKey,
            ripe: ripe,
          }, opts)));
        } else {
          nextTick(tryKey);
        }
      }).catch(reject);
    }
    tryKey();
  });
};

module.exports = Address;
