/**
 * Bitmessage library entry point. Just reexports common submodules.
 * @module bitmessage
 */

"use strict";

/** Common structures. */
exports.struct = require("./struct");
/** Working with WIF. */
exports.WIF = require("./wif");
/** Working with addresses. */
exports.Address = require("./address");
