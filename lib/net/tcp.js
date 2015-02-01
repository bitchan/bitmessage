/**
 * TCP transport for Node. Should be compatible with PyBitmessage.
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
