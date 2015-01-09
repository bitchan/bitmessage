/**
 * Worker routines for Node platform. This module tries to load native
 * addon and makes it available for Node.
 */

try {
  module.exports = require("../build/Release/worker");
} catch(e) {
  // Do nothing for a moment. Everything will work except the functions
  // that uses worker routines.
  // TODO(Kagami) Provide pure JS fallback.
}
