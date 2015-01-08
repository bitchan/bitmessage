/**
 * Working with Bitmessage addresses.
 * @see {@link https://bitmessage.org/wiki/Address}
 * @module bitmessage/address
 */

"use strict";

var objectAssign = Object.assign || require("object-assign");
var bufferEqual = require("buffer-equal");
var bs58 = require("bs58");
var assert = require("./util").assert;
var var_int = require("./structs").var_int;
var bmcrypto = require("./crypto");

/**
 * Create a new Bitmessage address object.
 * @param {?Object} opts - Address options
 * @constructor
 * @static
 */
function Address(opts) {
  if (!(this instanceof Address)) {
    return new Address(opts);
  }
  opts = opts || {};
  objectAssign(this, opts);
  this.version = this.version || 4;
  assert(this.version <= 4, "Version too high");
  assert(this.version >= 1, "Version too low");
  this.stream = this.stream || 1;
  if (this.ripe) {
    assertripelen(getripelen(this.ripe), this.version, this.ripe);
    if (this.ripe.length < 20) {
      var fullripe = new Buffer(20);
      fullripe.fill(0);
      this.ripe.copy(fullripe, 20 - this.ripe.length);
      this.ripe = fullripe;
    }
  }
}

/**
 * Parse Bitmessage address into address object.
 * @param {String} str - Address string (with or without `BM-` prefix)
 * @return {Address} Decoded address object.
 */
Address.decode = function(str) {
  str = str.trim();
  if (str.slice(0, 3) === "BM-") {
    str = str.slice(3);
  }

  var bytes = bs58.decode(str);
  var data = new Buffer(bytes.slice(0, -4));
  var checksum = new Buffer(bytes.slice(-4));
  assert(bufferEqual(checksum, getaddrchecksum(data)), "Bad checkum");

  var decoded = var_int.decode(data);
  var version = decoded.value;

  data = decoded.rest;
  decoded = var_int.decode(data);
  var stream = decoded.value;

  var ripe = decoded.rest;
  if (version === 4) {
    assert(ripe[0] !== 0, "Ripe encode error");
  }

  return new Address({version: version, stream: stream, ripe: ripe});
};

// Compute the Bitmessage checksum for the given data.
function getaddrchecksum(data) {
  return bmcrypto.sha512(bmcrypto.sha512(data)).slice(0, 4);
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
  return bmcrypto.ripemd160(bmcrypto.sha512(concat));
}

/**
 * Calculate the ripe hash of the address.
 * @param {?Object} opts - Options
 * @return {Buffer} Resulting ripe hash.
 */
Address.prototype.getRipe = function(opts) {
  var ripe;
  opts = opts || {};
  if (this.ripe) {
    ripe = this.ripe;
  } else {
    var signKey = this.signPrivateKey || this.signPublicKey;
    assert(signKey, "No signing key");
    var encKey = this.encPrivateKey || this.encPublicKey;
    assert(encKey, "No encryption key");
    ripe = keys2ripe(signKey, encKey);
  }
  var ripelen = getripelen(ripe);
  assertripelen(ripelen, this.version, ripe);
  if (opts.short) {
    return ripe.slice(20 - ripelen);
  } else {
    return ripe;
  }
};

// Get truncated ripe hash length.
function getripelen(ripe) {
  var zeroes = 0;
  for (var i = 0; i < 20, ripe[i] === 0; i++) {
    zeroes++;
  }
  return 20 - zeroes;
}

// Do neccessary checkings of the truncated ripe hash length depending
// on the address version.
function assertripelen(ripelen, version, ripe) {
  if (ripe) {
    assert(ripe.length <= 20, "Bad ripe");
  }
  switch (version) {
    case 1:
      assert(ripelen === 20, "Bad ripe length");
      break;
    case 2:
    case 3:
      assert(ripelen >= 18, "Ripe is too short");
      assert(ripelen <= 20, "Ripe is too long");
      break;
    case 4:
      assert(ripelen >= 4, "Ripe is too short");
      assert(ripelen <= 20, "Ripe is too long");
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
 * @return {string} Address string.
 */
Address.prototype.encode = function() {
  var ripe = this.getRipe({short: true});
  var data = Buffer.concat([
    var_int.encode(this.version),
    var_int.encode(this.stream),
    ripe,
  ]);
  var addr = Buffer.concat([data, getaddrchecksum(data)]);
  return "BM-" + bs58.encode(addr);
};

function popkey(obj, key) {
  var value = obj[key];
  delete obj[key];
  return value;
}

/**
 * Create new Bitmessage address from random encryption and signing
 * private keys.
 * @param {?Object} opts - Address options
 * @return {Address} Generated address object.
 */
Address.fromRandom = function(opts) {
  opts = objectAssign({}, opts);
  var version = opts.version = opts.version || 4;
  var ripelen = popkey(opts, "ripelen") || 19;
  assertripelen(ripelen, version);
  // Should the generated ripe length be strictly equal to the specified
  // (less or equal by default).
  var strictripelen = !!popkey(opts, "strictripelen");

  // TODO(Kagami): Speed it up using web workers in Browser.
  // TODO(Kagami): Bind to C++ version of this code in Node.
  var encPrivateKey, encPublicKey, ripe;
  var signPrivateKey = bmcrypto.getPrivate();
  var signPublicKey = bmcrypto.getPublic(signPrivateKey);
  var keysbuf = Buffer(130);
  signPublicKey.copy(keysbuf);
  while (true) {
    encPrivateKey = bmcrypto.getPrivate();
    encPublicKey = bmcrypto.getPublic(encPrivateKey);
    encPublicKey.copy(keysbuf, 65);
    ripe = bmcrypto.ripemd160(bmcrypto.sha512(keysbuf));
    var len = getripelen(ripe);
    if (
      (strictripelen && len === ripelen) ||
      (!strictripelen && len <= ripelen && checkripelen(ripelen, version))
    ) {
      // TODO(Kagami): Do we need to put all these properties or compute
      // them manually via ECMA5 getters/setters instead?
      opts.signPrivateKey = signPrivateKey;
      opts.signPublicKey = signPublicKey;
      opts.encPrivateKey = encPrivateKey;
      opts.encPublicKey = encPublicKey;
      opts.ripe = ripe;
      return new Address(opts);
    }
  }
};

module.exports = Address;
