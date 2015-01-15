/**
 * Working with Bitmessage user agents.
 * @see {@link https://bitmessage.org/wiki/User_Agent}
 * @module bitmessage/user-agent
 */

"use strict";

var var_str = require("./structs").var_str;
var BM_NAME = require("../package.json").name;
var BM_VERSION = require("../package.json").version;

/** User agent of the bitmessage library itself. */
var SELF = exports.SELF = [{name: BM_NAME, version: BM_VERSION}];

/**
 * Decode user agent stack.
 * NOTE: Decoding is rather loose and non-strict, it won't fail on bad
 * user agent format because it's not that important.
 * Also note that `rest` references input buffer.
 * @param {Buffer} buf - A buffer that starts with encoded user agent
 * @return {{software: Object[], length: number, rest: Buffer}}
 * Decoded user agent structure.
 */
exports.decode = function(buf) {
  var decoded = var_str.decode(buf);
  var software = [];
  if (decoded.str) {
    software = decoded.str.slice(1, -1).split("/");
    software = software.map(function(str) {
      // That's more readable than /([^:]*)(?::([^(]*)(?:\(([^)]*))?)?/
      var soft = {name: str};
      var semicolon = soft.name.indexOf(":");
      if (semicolon !== -1) {
        soft.version = soft.name.slice(semicolon + 1);
        soft.name = soft.name.slice(0, semicolon);
        var obracket = soft.version.indexOf("(");
        if (obracket !== -1) {
          soft.comments = soft.version.slice(obracket + 1);
          soft.version = soft.version.slice(0, obracket);
          var cbracket = soft.comments.indexOf(")");
          if (cbracket !== -1) {
            soft.comments = soft.comments.slice(0, cbracket);
          }
        }
      }
      return soft;
    });
  }
  return {software: software, length: decoded.length, rest: decoded.rest};
};

/**
 * Encode user agent. Most underlying software comes first.
 * @param {(Object[]|string[]|Object|string)} software - List of
 * software to encode
 * @return {Buffer} Encoded user agent.
 */
var encode = exports.encode = function(software) {
  if (!Array.isArray(software)) {
    software = [software];
  }
  var ua = software.map(function(soft) {
    if (typeof soft === "string") {
      return soft;
    }
    var version = soft.version || "0.0.0";
    var str = soft.name + ":" + version;
    if (soft.comments) {
      str += "(" + soft.comments + ")";
    }
    return str;
  }).join("/");
  return var_str.encode("/" + ua + "/");
};

/**
 * Encode bitmessage's user agent.
 * @return {Buffer} Encoded user agent.
 */
exports.encodeSelf = function() {
  return encode(SELF);
};

/**
 * Encode user agent with bitmessage's user agent underneath. Most
 * underlying software comes first.
 * @param {(Object[]|string[]|Object|string)} software - List of
 * software to encode
 * @return {Buffer} Encoded user agent.
 */
exports.encodeSelfWith = function(software) {
  software = SELF.concat(software);
  return encode(software);
};
