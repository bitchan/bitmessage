/**
 * Bitmessage library entry point. Just reexports common submodules.
 * @module bitmessage
 */

"use strict";

/**
 * Current protocol version.
 * @constant {number}
 */
exports.PROTOCOL_VERSION = require("./_util").PROTOCOL_VERSION;

/** [Common structures.]{@link module:bitmessage/structs} */
exports.structs = require("./structs");
/** [Messages.]{@link module:bitmessage/messages} */
exports.messages = require("./messages");
/** [Objects.]{@link module:bitmessage/objects} */
exports.objects = require("./objects");

/** [Working with WIF.]{@link module:bitmessage/wif} */
exports.WIF = require("./wif");
/** [Proof of work.]{@link module:bitmessage/pow} */
exports.POW = require("./pow");

/** [Working with addresses.]{@link module:bitmessage/address} */
exports.Address = require("./address");
/** [User agent.]{@link module:bitmessage/user-agent} */
exports.UserAgent = require("./user-agent");
