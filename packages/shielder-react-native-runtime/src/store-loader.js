let cachedStore = null;

function loadStore() {
  if (cachedStore) return cachedStore;

  const store = global.__SHIELDER_STORE__ ?? null;
  if (!store) return null;

  cachedStore = store;
  return cachedStore;
}

module.exports = { loadStore };
