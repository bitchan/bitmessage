/**
 * Bitmessage library entry point. Just reexports common submodules.
 * @module bitmessage
 */

"use strict";

/** Common structures. */
exports.struct = require("./struct");
/** Messages. */
exports.message = require("./message");
/** Objects. */
exports.object = require("./object");

/** Working with WIF. */
exports.WIF = require("./wif");
/** Proof of work. */
exports.POW = require("./pow");

/** Working with addresses. */
exports.Address = require("./address");
