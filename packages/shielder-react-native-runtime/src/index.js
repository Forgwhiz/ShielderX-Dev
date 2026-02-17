// index.js
// @shielderx/react-native-runtime

const { resolveSecret } = require("./resolver");

// CommonJS
module.exports = {
  resolveSecret
};

// ESModule compatibility for Metro / React Native
module.exports.default = {
  resolveSecret
};
