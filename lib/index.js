/**
 * Bitmessage library entry point. Just reexports common submodules.
 * @module bitmessage
 */

"use strict";

/**
 * `uint64_t` implementation used to represent such numbers in
 * JavaScript. Default is
 * [int64-native](https://www.npmjs.com/package/int64-native) for Node
 * platform and [node-int64](https://www.npmjs.com/package/node-int64)
 * for Browser. You may replace it with other library with the same API.
 */
exports.Int64 = require("int64-native");
/** Working with addresses. */
exports.Address = require("./address");
/** Working with WIF. */
exports.wif = require("./wif");
/** Core structures. */
exports.struct = require("./struct");
