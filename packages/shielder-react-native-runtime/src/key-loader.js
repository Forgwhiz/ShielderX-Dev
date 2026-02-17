let cachedKey = null;

function loadKey() {
  if (cachedKey) return cachedKey;

  const key = global.__SHIELDER_KEY__ ?? null;
  if (!key) return null;

  cachedKey = key;
  return cachedKey;
}

module.exports = { loadKey };
