"use strict";

exports.assert = function(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
};
