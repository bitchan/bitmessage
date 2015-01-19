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
var PubkeyBitfield = require("./structs").PubkeyBitfield;
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
  opts = objectAssign({}, opts);
  // Pull out version right away because it may be needed in setters.
  this.version = popkey(opts, "version") || 4;
  assert(this.version <= 4, "Version too high");
  assert(this.version >= 1, "Version too low");
  // Set defaults.
  opts.stream = opts.stream || 1;
  opts.behavior = opts.behavior ||
                  PubkeyBitfield().set(PubkeyBitfield.DOES_ACK);
  // Merge remained values.
  objectAssign(this, opts);
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

/**
 * Calculate the ripe hash of the address.
 * @param {?Object} opts - Options
 * @return {Buffer} Resulting ripe hash.
 */
Address.prototype.getRipe = function(opts) {
  opts = opts || {};
  var ripe = this.ripe;
  if (opts.short) {
    return ripe.slice(20 - getripelen(ripe));
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
      opts.signPrivateKey = signPrivateKey;
      opts.encPrivateKey = encPrivateKey;
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
  if (typeof opts === "string") {
    opts = {passphrase: opts};
  } else {
    opts = objectAssign({}, opts);
  }
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
      opts.signPrivateKey = signPrivateKey;
      opts.encPrivateKey = encPrivateKey;
      return new Address(opts);
    }
    signnonce += 2;
    encnonce += 2;
  }
};

Object.defineProperty(Address.prototype, "signPrivateKey", {
  get: function() {
    return this._signPrivateKey;
  },
  set: function(signPrivateKey) {
    this._signPrivateKey = signPrivateKey;
    // Invalidate cached values;
    delete this._signPublicKey;
    delete this._ripe;
  },
});

Object.defineProperty(Address.prototype, "signPublicKey", {
  get: function() {
    if (this._signPublicKey) {
      return this._signPublicKey;
    } else if (this.signPrivateKey) {
      this._signPublicKey = bmcrypto.getPublic(this.signPrivateKey);
      return this._signPublicKey;
    } else {
      throw new Error("No signing key");
    }
  },
  set: function(signPublicKey) {
    this._signPublicKey = signPublicKey;
  },
});

Object.defineProperty(Address.prototype, "encPrivateKey", {
  get: function() {
    return this._encPrivateKey;
  },
  set: function(encPrivateKey) {
    this._encPrivateKey = encPrivateKey;
    // Invalidate cached values;
    delete this._encPublicKey;
    delete this._ripe;
  },
});

Object.defineProperty(Address.prototype, "encPublicKey", {
  get: function() {
    if (this._encPublicKey) {
      return this._encPublicKey;
    } else if (this.encPrivateKey) {
      this._encPublicKey = bmcrypto.getPublic(this.encPrivateKey);
      return this._encPublicKey;
    } else {
      throw new Error("No encryption key");
    }
  },
  set: function(encPublicKey) {
    this._encPublicKey = encPublicKey;
  },
});

Object.defineProperty(Address.prototype, "ripe", {
  get: function() {
    if (this._ripe) {
      return this._ripe;
    }
    var dataToHash = Buffer.concat([this.signPublicKey, this.encPublicKey]);
    this._ripe = bmcrypto.ripemd160(bmcrypto.sha512(dataToHash));
    return this._ripe;
  },
  set: function(ripe) {
    assertripelen(getripelen(ripe), this.version, ripe);
    if (ripe.length < 20) {
      var fullripe = new Buffer(20);
      fullripe.fill(0);
      ripe.copy(fullripe, 20 - ripe.length);
      ripe = fullripe;
    }
    this._ripe = ripe;
  },
});

module.exports = Address;
