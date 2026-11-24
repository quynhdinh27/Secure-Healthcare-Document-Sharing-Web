import { requiredStrings } from '../encoding.js'

function withKeyStore(userId, keyId, mode, operation) {
  requiredStrings({ userId, keyId }, ['userId', 'keyId'])
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('medshare-crypto', 1)
    open.onupgradeneeded = () => open.result.createObjectStore('privateKeys')
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const db = open.result
      const transaction = db.transaction('privateKeys', mode)
      transaction.onabort = () => { db.close(); reject(transaction.error) }
      try {
        const request = operation(transaction.objectStore('privateKeys'), [userId, keyId])
        transaction.oncomplete = () => { db.close(); resolve(request.result) }
      } catch (error) {
        transaction.abort()
        reject(error)
      }
    }
  })
}

export function saveLocalKey(userId, keyId, key) {
  if (key?.type !== 'private' || key.extractable !== false) throw new TypeError('Expected a non-extractable private key')
  return withKeyStore(userId, keyId, 'readwrite', (store, id) => store.put(key, id))
}

export const loadLocalKey = (userId, keyId) => withKeyStore(userId, keyId, 'readonly', (store, id) => store.get(id))
export const removeLocalKey = (userId, keyId) => withKeyStore(userId, keyId, 'readwrite', (store, id) => store.delete(id))
