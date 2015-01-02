/**
 * Bitmessage library entry point. Just reexports common submodules.
 * @module bitmessage
 */

"use strict";

/** Working with addresses. */
exports.Address = require("./address");
/** Working with WIF. */
exports.wif = require("./wif");
/** Core structures. */
exports.struct = require("./struct");
