// Run test nodes for all known transports so we can test library in
// functional test suites. Stop nodes when testing is complete.

// Note that this file is executed only on Node.js platform.

var path = require("path");
var child = require("child_process");

var TCP_NODE_PATH = path.join(__dirname, "tcp-node.js");
var WS_NODE_PATH = path.join(__dirname, "ws-node.js");

function spawn(path) {
  var p = child.spawn("node", [path]);
  p.stdout.on("data", function(data) {
    console.log("Info from", path, ":", data.toString().trim());
  });
  p.stderr.on("data", function(err) {
    console.log("Error from", path, ":", err.toString());
  });
  return p;
}

module.exports = function() {
  function cleanup(doExit) {
    return function(err) {
      try {
        tcpNode.kill("SIGKILL");
      } catch(e) {
        console.log(e.stack);
      }
      try {
        wsNode.kill("SIGKILL");
      } catch(e) {
        console.log(e.stack);
      }
      if (err && err.stack) console.log(err.stack);
      if (doExit) process.exit(1);
    };
  }

  var tcpNode = spawn(TCP_NODE_PATH);
  var wsNode = spawn(WS_NODE_PATH);
  process.on("exit", cleanup());
  process.on("SIGINT", cleanup(true));
  process.on("uncaughtException", cleanup(true));
};
