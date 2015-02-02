var testMode = (global.__env__ || process.env).TEST_MODE;

if (testMode !== "functional") {
  describe("Unit tests", function() {
    require("./unit");
  });
}

if (testMode !== "unit") {
  // For Browser tests nodes are runned from karma.conf.js because we
  // are _already_ in browser context here.
  if (!process.browser) require("./run-test-nodes.js")();

  describe("Functional tests", function() {
    require("./functional");
  });
}
