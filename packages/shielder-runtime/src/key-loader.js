const fs = require("fs");
const path = require("path");
const { ShielderRuntimeError } = require("./errors");
const { ShielderKeyNotFoundError } = require("./errors");



function loadProjectKey() {
  const keyPath = path.join(process.cwd(), ".shielder.key");

//   if (!fs.existsSync(keyPath)) {
//     throw new ShielderRuntimeError(
//       "Project key (.shielder.key) not found."
//     );
//   }

  if (!fs.existsSync(keyPath)) {
  throw new ShielderKeyNotFoundError();
}

  return fs.readFileSync(keyPath);
}

module.exports = { loadProjectKey };
