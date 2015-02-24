// Run test nodes for all known transports so we can test library in
// functional test suites. Stop nodes when testing is complete.

// Note that this file is executed only on Node.js platform.

var path = require("path");
var child = require("child_process");

function spawn(name) {
  var p = child.spawn("node", [path.join(__dirname, name)]);
  p.stdout.on("data", function(data) {
    console.log("Info from " + name + ": " + data.toString().trim());
  });
  p.stderr.on("data", function(err) {
    console.log("Error from " + name + ": " + err.toString().trim());
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

  process.on("exit", cleanup());
  process.on("SIGINT", cleanup(true));

  var tcpNode = spawn("tcp-node.js");
  var wsNode = spawn("ws-node.js");
};
