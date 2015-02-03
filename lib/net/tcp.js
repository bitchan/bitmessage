/**
 * TCP transport. Should be compatible with PyBitmessage. Available only
 * for Node.js.
 * @module bitmessage/net/tcp
 */

"use strict";

var inherits = require("inherits");
var BaseTransport = require("./base").BaseTransport;

/**
 * TCP transport constructor.
 * @constructor
 * @static
 */
function Transport() {
  Transport.super_.call(this);
}

inherits(Transport, BaseTransport);

exports.Transport = Transport;
