import React, { useState } from 'react';
import { openDB } from 'idb';
import CryptoJS from 'crypto-js';

const App = () => {
  // State variables
  const [privateKey, setPrivateKey] = useState('');
  const [password, setPassword] = useState('');
  const [retrievedKey, setRetrievedKey] = useState('');
  const [message, setMessage] = useState('');

  // Initialize IndexedDB
  const initDB = async () => {
    return openDB('KeyManagerDB', 1, {
      upgrade(db) {
        if (!db.objectStoreNames.contains('keys')) {
          db.createObjectStore('keys', { keyPath: 'id' });
        }
      },
    });
  };

  // Save key to IndexedDB
  const saveKeyToDB = async (id, encryptedKey) => {
    const db = await initDB();
    await db.put('keys', { id, encryptedKey });
  };

  // Retrieve key from IndexedDB
  const getKeyFromDB = async (id) => {
    const db = await initDB();
    return db.get('keys', id);
  };

  // Delete key from IndexedDB
  const deleteKeyFromDB = async (id) => {
    const db = await initDB();
    await db.delete('keys', id);
  };

  const IV_LENGTH = 16; // Length of IV in bytes

  // Encrypt Private Key
  const encryptPrivateKey = (text, password) => {
    const iv = CryptoJS.lib.WordArray.random(IV_LENGTH);
    const key = CryptoJS.PBKDF2(password, password, { keySize: 256 / 32 });

    const encrypted = CryptoJS.AES.encrypt(text, key, { iv });

    // Combine IV and ciphertext in the format IV:ciphertext
    const encryptedKey =
      iv.toString(CryptoJS.enc.Hex) + ':' + encrypted.ciphertext.toString(CryptoJS.enc.Hex);

    return encryptedKey;
  };

  // Decrypt Private Key
  const decryptPrivateKey = (encryptedKey, password) => {
    const [ivHex, ciphertextHex] = encryptedKey.split(':');

    const iv = CryptoJS.enc.Hex.parse(ivHex);
    const ciphertext = CryptoJS.enc.Hex.parse(ciphertextHex);

    const key = CryptoJS.PBKDF2(password, password, { keySize: 256 / 32 });

    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext },
      key,
      { iv }
    );

    return decrypted.toString(CryptoJS.enc.Utf8);
  };

  // Generate a new private key
  const generateKey = () => {
    const newKey = `key-${Math.random().toString(36).substring(2, 15)}`;
    setPrivateKey(newKey);
    setMessage('New private key generated.');
  };

  // Save the generated key
  const saveKey = async () => {
    if (!privateKey || !password) {
      alert('Please generate a key and enter a password!');
      return;
    }
    const encryptedKey = encryptPrivateKey(privateKey, password);
    await saveKeyToDB('userKey', encryptedKey);
    setMessage('Key saved securely.');
  };

  // Retrieve the key
  const retrieveKey = async () => {
    const keyData = await getKeyFromDB('userKey');
    if (!keyData) {
      alert('No key found!');
      return;
    }
    const { encryptedKey } = keyData;
    try {
      const decryptedKey = decryptPrivateKey(encryptedKey, password);
      setRetrievedKey(decryptedKey);
      setMessage('Key retrieved successfully.');
    } catch (error) {
      alert('Incorrect password!');
    }
  };

  // Delete the key
  const deleteKey = async () => {
    await deleteKeyFromDB('userKey');
    setMessage('Key deleted successfully.');
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>A-MACI Key Manager</h1>

      <button onClick={generateKey} style={{ margin: '10px' }}>
        Generate Key
      </button>
      {privateKey && <p><strong>Private Key:</strong> {privateKey}</p>}

      <div style={{ margin: '10px 0' }}>
        <input
          type="password"
          placeholder="Enter password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{ padding: '5px', marginRight: '10px' }}
        />
        <button onClick={saveKey} style={{ margin: '5px' }}>
          Save Key
        </button>
        <button onClick={retrieveKey} style={{ margin: '5px' }}>
          Retrieve Key
        </button>
        <button onClick={deleteKey} style={{ margin: '5px' }}>
          Delete Key
        </button>
      </div>

      {retrievedKey && (
        <p>
          <strong>Retrieved Key:</strong> {retrievedKey}
        </p>
      )}
      {message && <p><em>{message}</em></p>}
    </div>
  );
};

export default App;
