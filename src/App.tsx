import React, { useState } from 'react';
import { openDB } from 'idb';
import CryptoJS from 'crypto-js';

const App = () => {
  const [privateKey, setPrivateKey] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [password, setPassword] = useState('');
  const [retrievedPrivateKey, setRetrievedPrivateKey] = useState('');
  const [retrievedPublicKey, setRetrievedPublicKey] = useState('');
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

  // Save both keys to IndexedDB
  const saveKeysToDB = async (id, encryptedPrivateKey, publicKey) => {
    const db = await initDB();
    await db.put('keys', { id, encryptedPrivateKey, publicKey });
  };

  // Retrieve both keys from IndexedDB
  const getKeysFromDB = async (id) => {
    const db = await initDB();
    return db.get('keys', id);
  };

  // Encrypt Private Key using AES
  const encryptPrivateKey = (privateKey, password) => {
    const iv = CryptoJS.lib.WordArray.random(16); // Generate random IV
    const key = CryptoJS.PBKDF2(password, password, { keySize: 256 / 32 });

    const encrypted = CryptoJS.AES.encrypt(privateKey, key, { iv });

    // Combine IV and ciphertext in the format: IV:ciphertext
    const encryptedKey =
      iv.toString(CryptoJS.enc.Hex) + ':' + encrypted.ciphertext.toString(CryptoJS.enc.Hex);

    return encryptedKey;
  };

  // Decrypt Private Key using AES
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

  // Generate ECDSA Key Pair (Private and Public Key)
  const generateKeyPair = async () => {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // Curve P-256 for ECDSA
      },
      true, // Whether the key is extractable
      ['sign', 'verify'] // Key usage
    );

    const privateKeyData = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const publicKeyData = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);

    const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyData)));
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyData)));

    setPrivateKey(privateKeyBase64);
    setPublicKey(publicKeyBase64);
    setMessage('New key pair generated.');
  };

  // Save both public and encrypted private keys
  const saveKeys = async () => {
    if (!privateKey || !password) {
      alert('Please generate a key pair and enter a password!');
      return;
    }

    const encryptedPrivateKey = encryptPrivateKey(privateKey, password);
    await saveKeysToDB('userKeys', encryptedPrivateKey, publicKey);
    setMessage('Both keys saved securely.');
  };

  // Retrieve both keys
  const retrieveKeys = async () => {
    const keyData = await getKeysFromDB('userKeys');
    if (!keyData) {
      alert('No key found!');
      return;
    }

    const { encryptedPrivateKey, publicKey } = keyData;
    try {
      const decryptedPrivateKey = decryptPrivateKey(encryptedPrivateKey, password);
      setRetrievedPrivateKey(decryptedPrivateKey);
      setRetrievedPublicKey(publicKey);
      setMessage('Keys retrieved successfully.');
    } catch (error) {
      alert('Incorrect password!');
    }
  };

  // Delete keys from IndexedDB
  const deleteKeys = async () => {
    await initDB();
    const db = await openDB('KeyManagerDB', 1);
    await db.delete('keys', 'userKeys');
    setMessage('Keys deleted successfully.');
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>Key Manager</h1>

      <button onClick={generateKeyPair} style={{ margin: '10px' }}>
        Generate Key Pair
      </button>
      {privateKey && <p><strong>Private Key:</strong> {privateKey}</p>}
      {publicKey && <p><strong>Public Key:</strong> {publicKey}</p>}

      <div style={{ margin: '10px 0' }}>
        <input
          type="password"
          placeholder="Enter password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{ padding: '5px', marginRight: '10px' }}
        />
        <button onClick={saveKeys} style={{ margin: '5px' }}>
          Save Keys
        </button>
        <button onClick={retrieveKeys} style={{ margin: '5px' }}>
          Retrieve Keys
        </button>
        <button onClick={deleteKeys} style={{ margin: '5px' }}>
          Delete Keys
        </button>
      </div>

      {retrievedPrivateKey && (
        <p><strong>Retrieved Private Key:</strong> {retrievedPrivateKey}</p>
      )}
      {retrievedPublicKey && (
        <p><strong>Retrieved Public Key:</strong> {retrievedPublicKey}</p>
      )}

      {message && <p><em>{message}</em></p>}
    </div>
  );
};

export default App;
