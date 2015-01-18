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
  if (str instanceof Address) {
    return str;
  }

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
  var dataToHash = Buffer.concat([signPublicKey, encPublicKey]);
  return bmcrypto.ripemd160(bmcrypto.sha512(dataToHash));
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

/**
 * Calculate the address tag.
 * @return {Buffer} A 32-byte address tag.
 */
Address.prototype.getTag = function() {
  var ripe = this.getRipe();
  var dataToHash = Buffer.concat([
    var_int.encode(this.version),
    var_int.encode(this.stream),
    ripe,
  ]);
  var hash = bmcrypto.sha512(bmcrypto.sha512(dataToHash));
  return hash.slice(32);
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

  // TODO(Kagami): Speed it up using web workers in Browser.
  // TODO(Kagami): Bind to C++ version of this code in Node.
  var encPrivateKey, encPublicKey, ripe, len;
  var signPrivateKey = bmcrypto.getPrivate();
  var signPublicKey = bmcrypto.getPublic(signPrivateKey);
  var keysbuf = new Buffer(130);
  signPublicKey.copy(keysbuf);
  while (true) {
    encPrivateKey = bmcrypto.getPrivate();
    encPublicKey = bmcrypto.getPublic(encPrivateKey);
    encPublicKey.copy(keysbuf, 65);
    ripe = bmcrypto.ripemd160(bmcrypto.sha512(keysbuf));
    len = getripelen(ripe);
    if (len <= ripelen && checkripelen(len, version)) {
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

/**
 * Create new Bitmessage address from passphrase.
 * @param {?Object} opts - Address options
 * @return {Address} Generated address object.
 */
Address.fromPassphrase = function(opts) {
  opts = objectAssign({}, opts);
  var version = opts.version = opts.version || 4;
  var ripelen = popkey(opts, "ripelen") || 19;
  assertripelen(ripelen, version);
  var passphrase = popkey(opts, "passphrase");

  // TODO(Kagami): Speed it up using web workers in Browser.
  // TODO(Kagami): Bind to C++ version of this code in Node.
  var signPrivateKey, signPublicKey, encPrivateKey, encPublicKey;
  var ripe, len, tmp;
  var signnonce = 0;
  var encnonce = 1;
  var keysbuf = new Buffer(130);
  // XXX(Kagami): Spec doesn't mention encoding, using UTF-8.
  var phrasebuf = new Buffer(passphrase, "utf8");
  while (true) {
    // TODO(Kagami): We may slightly optimize it and pre-create tmp
    // buffers based on the encoded nonce size (1, 3, 5 and 9 bytes).
    tmp = Buffer.concat([phrasebuf, var_int.encode(signnonce)]);
    signPrivateKey = bmcrypto.sha512(tmp).slice(0, 32);
    signPublicKey = bmcrypto.getPublic(signPrivateKey);
    signPublicKey.copy(keysbuf);

    tmp = Buffer.concat([phrasebuf, var_int.encode(encnonce)]);
    encPrivateKey = bmcrypto.sha512(tmp).slice(0, 32);
    encPublicKey = bmcrypto.getPublic(encPrivateKey);
    encPublicKey.copy(keysbuf, 65);

    ripe = bmcrypto.ripemd160(bmcrypto.sha512(keysbuf));
    len = getripelen(ripe);
    if (len <= ripelen && checkripelen(len, version)) {
      // TODO(Kagami): Do we need to put all these properties or compute
      // them manually via ECMA5 getters/setters instead?
      opts.signPrivateKey = signPrivateKey;
      opts.signPublicKey = signPublicKey;
      opts.encPrivateKey = encPrivateKey;
      opts.encPublicKey = encPublicKey;
      opts.ripe = ripe;
      return new Address(opts);
    }
    signnonce += 2;
    encnonce += 2;
  }
};

module.exports = Address;
