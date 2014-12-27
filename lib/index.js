/**
 * Main Bitmessage module. Just reexports all public submodules.
 * @module bitmessage
 */

"use strict";

// uint64_t implementation used for operations with int64. You may
// replace it with other library with the same API.
exports.Int64 = require("int64-native");
exports.Address = require("./address");
