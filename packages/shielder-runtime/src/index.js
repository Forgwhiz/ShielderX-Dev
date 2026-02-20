// index.js
// @shielderx/runtime - Node.js version

const { resolveSecret } = require("./resolver");

// CommonJS
module.exports = {
  resolveSecret
};

// ESModule compatibility
module.exports.default = {
  resolveSecret
};