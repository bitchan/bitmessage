/**
 * Bitmessage library entry point. Just reexports common submodules.
 * @module bitmessage
 */

"use strict";

/** Common structures. */
exports.structs = require("./structs");
/** Messages. */
exports.messages = require("./messages");
/** Objects. */
exports.objects = require("./objects");

/** Working with WIF. */
exports.WIF = require("./wif");
/** Proof of work. */
exports.POW = require("./pow");

/** Working with addresses. */
exports.Address = require("./address");
