/**
 * Working with Bitmessage addresses.
 * @module bitmessage/address
 */

"use strict";

require("es6-promise").polyfill();
var assert = require("assert");
var bufferEqual = require("buffer-equal");
var bs58 = require("bs58");
var varint = require("./varint");
var bmcrypto = require("./crypto");

/**
 * Parse Bitmessage address into address object.
 * @param {String} str - Address string (with or without `BM-` prefix)
 * @return {Promise.<Address,Error>} Decoded address object
 */
exports.decode = function(str) {
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
    assertversion(version);

    data = decoded.rest;
    decoded = varint.decode(data);
    var stream = decoded.value;
    assertstream(stream);

    var ripe = decoded.rest;
    var ripelen = ripe.length;
    assertripelen(ripelen, version);
    if (version === 4) {
      assert(ripe[0] !== 0, "Ripe decode error");
    }

    // Prevent extra allocation. God, kill me please for premature
    // optimizations.
    if (ripelen < 20) {
      var zeroes = new Buffer(Array(20 - ripelen));
      ripe = Buffer.concat([zeroes, ripe]);
    }
    return {version: version, stream: stream, ripe: ripe};
  });
};

// Compute the Bitmessage checksum for the given data.
function getchecksum(data) {
  return bmcrypto.sha512(data).then(bmcrypto.sha512).then(function(dhash) {
    return dhash.slice(0, 4);
  });
}

// Get RIPEMD160(SHA512(SIGN_PUBLIC_KEY || ENC_PUBLIC_KEY))
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
 * Get Ripe hash for the given address object.
 * @param {Address} addr - Address object
 * @param {?Object} opts - Options
 * @return {Buffer} Resulting Ripe hash.
 */
function getRipe(addr, opts) {
  var signKey = addr.signPrivateKey || addr.signPublicKey;
  assert(signKey, "No signing key");
  var encKey = addr.encPrivateKey || addr.encPublicKey;
  assert(encKey, "No encryption key");
  opts = opts || {};
  return keys2ripe(signKey, encKey).then(function(ripe) {
    if (opts.short) {
      var ripelen = getripelen(ripe);
      return ripe.slice(20 - ripelen);
    } else {
      return ripe;
    }
  });
}
exports.getRipe = getRipe;

// Do neccessary checkings of the address version.
function assertversion(version) {
  assert(version <= 4, "Version too high");
  assert(version >= 1, "Version too low");
}

// Do neccessary checkings of the stream number.
function assertstream(stream) {
  assert(stream, "No stream");
}

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
      throw new Error("Wrong version");
  }
}

// The same as `assertripelen` but return true/false instead of throw an
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
 * @param {Address} addr - Address object
 * @return {Promise.<string,Error>} Address string
 */
exports.encode = function(addr) {
  var version, stream, ripepromise;
  try {
    version = addr.version;
    assertversion(version);
    stream = addr.stream;
    assertstream(stream);

    if (addr.ripe) {
      ripepromise = Promise.resolve(addr.ripe);
    } else {
      ripepromise = getRipe(addr);
    }
  } catch (e) {
    return Promise.reject(e);
  }

  return ripepromise.then(function(ripe) {
    var ripelen = getripelen(ripe);
    assertripelen(ripelen, version);
    // Skip leading zeroes.
    ripe = ripe.slice(20 - ripelen);
    var data = Buffer.concat([
      varint.encode(version),
      varint.encode(stream),
      ripe,
    ]);
    return getchecksum(data).then(function(checksum) {
      var addr = Buffer.concat([data, checksum]);
      return "BM-" + bs58.encode(addr);
    });
  });
};

/**
 * Create new Bitmessage address using random encryption and signing
 * private keys.
 * @param {?Object} opts - Address options
 * @return {Promise.<Address,Error>} Generated address object
 */
exports.getRandom = function(opts) {
  var version, stream, ripelen, signPrivateKey;
  try {
    opts = opts || {};
    version = opts.version || 4;
    assertversion(version);
    stream = opts.stream || 1;
    assertstream(version);
    ripelen = opts.ripelen || 19;
    assertripelen(ripelen, version);
    // Place it to try-catch since there might be not enough entropy to
    // generate the key and the function will fail.
    signPrivateKey = bmcrypto.getPrivate();
  } catch(e) {
    return Promise.reject(e);
  }
  var nextTick = typeof setImmediate === "undefined" ?
                 process.nextTick :
                 setImmediate;
  // Should the generated Ripe length be strictly equal to the specified
  // (less-or-equal by default);
  var strictripelen = !!opts.strictripelen;
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
      var encPrivateKey;
      try {
        encPrivateKey = bmcrypto.getPrivate();
      } catch(e) {
        reject(e);
      }
      return keys2ripe(signPublicKey, encPrivateKey).then(function(ripe) {
        console.log(ripe);
        var len = getripelen(ripe);
        if (
          (strictripelen && len === ripelen) ||
          (!strictripelen && len <= ripelen && checkripelen(ripelen, version))
        ) {
          resolve({
            version: version,
            stream: stream,
            signPrivateKey: signPrivateKey,
            encPrivateKey: encPrivateKey,
          });
        } else {
          nextTick(tryKey);
        }
      }).catch(reject);
    }
    tryKey();
  });
};
