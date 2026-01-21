class ShielderRuntimeError extends Error {
  constructor(message) {
    super(message);
    this.name = "ShielderRuntimeError";
  }
}

class ShielderKeyNotFoundError extends ShielderRuntimeError {
  constructor() {
    super("Project key (.shielder.key) not found.");
  }
}

class ShielderStoreNotFoundError extends ShielderRuntimeError {
  constructor() {
    super("Secret store (.ai-secret-guard.json) not found.");
  }
}

class ShielderSecretNotFoundError extends ShielderRuntimeError {
  constructor(placeholder) {
    super(`Secret not found for placeholder: ${placeholder}`);
  }
}

module.exports = {
  ShielderRuntimeError,
  ShielderKeyNotFoundError,
  ShielderStoreNotFoundError,
  ShielderSecretNotFoundError
};
