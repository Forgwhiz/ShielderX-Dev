export function initShielder({ key, store }) {
  if (key) {
    global.__SHIELDER_KEY__ = key;
  }

  if (store) {
    global.__SHIELDER_STORE__ = store;
  }
}
