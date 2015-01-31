/**
 * Working with Bitmessage user agents.
 * @see {@link https://bitmessage.org/wiki/User_Agent}
 * @module bitmessage/user-agent
 */

"use strict";

var var_str = require("./structs").var_str;
var BM_NAME = require("../package.json").name;
var BM_VERSION = require("../package.json").version;

/**
 * User agent of the bitmessage library itself.
 * @constant {Object[]}
 * @static
 */
var SELF = exports.SELF = [{name: BM_NAME, version: BM_VERSION}];

/**
 * Decode user agent's `var_str`. Just an alias for
 * [var_str.decode]{@link module:bitmessage/structs.var_str.decode}.
 * @function
 */
exports.decode = var_str.decode;

/**
 * Parse raw user agent into software stack list. Most underlying
 * software comes first.  
 * NOTE: Decoding is rather loose, it won't fail on bad user agent
 * format because it's not that important.
 * @param {string} str - Raw user agent string
 * @return {Object[]} Parsed user agent.
 */
exports.parse = function(str) {
  var software = [];
  if (str.length > 2 && str[0] === "/" && str[str.length - 1] === "/") {
    software = str.slice(1, -1).split("/");
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
  return software;
};

/**
 * Encode user agent into `var_str` Buffer. Most underlying software
 * comes first.
 * @param {(Object[]|string[]|string)} software - List of software to
 * encode or just raw user agent string
 * @return {Buffer} Encoded user agent.
 * @function
 * @static
 */
var encode = exports.encode = function(software) {
  var ua;
  if (Array.isArray(software)) {
    ua = software.map(function(soft) {
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
    ua = "/" + ua + "/";
  } else {
    ua = software;
  }
  return var_str.encode(ua);
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
