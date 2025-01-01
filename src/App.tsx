import React, { useState, useEffect } from "react";
import { openDB, IDBPDatabase } from "idb";
import CryptoJS from "crypto-js";
import EC from "elliptic";

type Key = {
  name: string;
  publicKey: string;
  encryptedPrivateKey: string;
  status: "active" | "inactive";
};

const App: React.FC = () => {
  const [keysList, setKeysList] = useState<Key[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const ec = new EC.ec("secp256k1");

  // Initialize IndexedDB
  const initDB = async (): Promise<IDBPDatabase> => {
    return openDB("KeyManagerDB", 1, {
      upgrade(db) {
        if (!db.objectStoreNames.contains("keys")) {
          db.createObjectStore("keys", { keyPath: "publicKey" });
        }
      },
    });
  };

  // Retrieve all keys from IndexedDB
  const retrieveKeys = async (): Promise<void> => {
    setLoading(true);
    const db = await initDB();
    const keys = await db.getAll("keys");
    setKeysList(keys);
    setLoading(false);
  };

  // Generate a new key pair
  const generateKeyPair = async (): Promise<void> => {
    const keyName = prompt("Enter a name for the key pair:");
    if (!keyName) {
      alert("Key name is required!");
      return;
    }

    const password = prompt("Enter a password to secure the private key:");
    if (!password) {
      alert("Password is required to generate keys!");
      return;
    }

    setLoading(true);

    try {
      const keyPair = ec.genKeyPair();
      const publicKey = keyPair.getPublic("hex");
      const privateKey = keyPair.getPrivate("hex");

      // Encrypt the private key
      const iv = CryptoJS.lib.WordArray.random(16);
      const key = CryptoJS.PBKDF2(password, password, { keySize: 256 / 32 });
      const encrypted = CryptoJS.AES.encrypt(privateKey, key, { iv });
      const encryptedPrivateKey = `${iv.toString(CryptoJS.enc.Hex)}:${encrypted.ciphertext.toString(CryptoJS.enc.Hex)}`;

      // Save the key pair to IndexedDB
      const db = await initDB();
      await db.put("keys", { name: keyName, publicKey, encryptedPrivateKey, status: "inactive" });

      alert("Key pair generated and saved successfully!");

      // setMessage("Key pair generated and saved successfully.");
      retrieveKeys();

      alert("Key pair generated and saved successfully!");
    } catch (error) {
      alert("Error generating key pair.");
    } finally {
      setLoading(false);
    }
  };

  // Decrypt Private Key using AES
  const decryptPrivateKey = (encryptedKey: string, password: string): string | null => {
    try {
      const [ivHex, ciphertextHex] = encryptedKey.split(":");
      const iv = CryptoJS.enc.Hex.parse(ivHex);
      const ciphertext  = CryptoJS.enc.Hex.parse(ciphertextHex);

      const key = CryptoJS.PBKDF2(password, password, { keySize: 256 / 32 });

      const decrypted  = CryptoJS.AES.decrypt({ ciphertext  } as any, key, { iv });

      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      return null;
    }
  };

  // Get Private Key for a specific Public Key
  const getPrivateKey = (publicKey: string, encryptedPrivateKey: string): void => {
    const password = prompt(`Enter the password to retrieve the private key for ${publicKey}:`);
    if (!password) {
      alert("Password is required!");
      return;
    }

    const privateKey = decryptPrivateKey(encryptedPrivateKey, password);
    if (privateKey) {
      alert(`Private Key: ${privateKey}`);
      // setMessage(`Private Key for ${publicKey}: ${privateKey}`);
    } else {
      alert("Invalid password! Unable to retrieve the private key.");
      // setMessage("Invalid password! Unable to retrieve the private key.");
    }
  };

  // Toggle status between "active" and "inactive"
  const toggleStatus = async (publicKey: string, currentStatus: "active" | "inactive"): Promise<void> => {
    setLoading(true);

    const newStatus = currentStatus === "inactive" ? "active" : "inactive";

    const db = await initDB();
    const key = await db.get("keys", publicKey);

    if (key) {
      key.status = newStatus;
      await db.put("keys", key);

      // setActionMessage(`Key status updated to ${newStatus}.`);
      retrieveKeys();
      alert(`Key status updated to ${newStatus}.`);
    } else {
      alert("Key not found.");
    }

    setLoading(false);
  };

  // Delete key from IndexedDB
  const deleteKeyFromDB = async (publicKey: string): Promise<void> => {
    setLoading(true);

    const db = await initDB();
    await db.delete("keys", publicKey);
    alert("Key deleted successfully.");
    // setMessage("Key deleted successfully.");
    retrieveKeys();

    setLoading(false);
  };

  // Sign a message using a private key
  const signMessage = (publicKey: string, encryptedPrivateKey: string): void => {
    const password = prompt(`Enter the password to sign a message for ${publicKey}:`);
    if (!password) {
      alert("Password is required!");
      return;
    }

    const privateKey = decryptPrivateKey(encryptedPrivateKey, password);
    if (privateKey) {
      const msg = prompt("Enter the message to sign:");
      if (msg) {
        const key = ec.keyFromPrivate(privateKey);
        const signature = key.sign(msg);
        const signatureHex = signature.toDER("hex");
        alert(`Message signed! Signature: ${signatureHex}`);
        // setMessage(`Message signed! Signature: ${signatureHex}`);
      }
    } else {
      alert("Invalid password! Unable to retrieve the private key.");
      // setMessage("Invalid password! Unable to retrieve the private key.");
    }
  };

  useEffect(() => {
    retrieveKeys();
  }, []);

  return (
    <div style={{
      fontFamily: "Arial, sans-serif", color: "#fff", 
      display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", height: "100vh", width: "100vw"
    }}>
      <h1 style={{ textAlign: "center", color: "#fff" }}>Key Manager</h1>
      <div style={{ marginBottom: "20px", display: "flex", justifyContent: "center" , flexWrap:"wrap"}}>
        <button
          onClick={generateKeyPair}
          style={{
            padding: "10px 20px", marginRight: "10px", backgroundColor: "white", color: "black", border: "none",marginTop:"20px" ,borderRadius: "5px",
            cursor: "pointer", opacity: loading ? 0.5 : 1
          }}
          disabled={loading}
        >
          {loading ? "Generating..." : "Generate Key Pair"}
        </button>
        <button
          onClick={retrieveKeys}
          style={{
            padding: "10px 20px", backgroundColor: "white", color: "black", border: "none", borderRadius: "5px",
            cursor: "pointer", opacity: loading ? 0.5 : 1,marginTop:"20px" 
          }}
          disabled={loading}
        >
          {loading ? "Loading..." : "Retrieve Keys"}
        </button>
      </div>

      {loading && <div style={{ textAlign: "center", fontSize: "18px", marginTop: "20px" }}>Loading...</div>}

      {keysList.length > 0 ? (
        <ul style={{ listStyleType: "none", padding: 0, marginTop: "20px" }}>
          {keysList.map(({ name, publicKey, encryptedPrivateKey, status }) => (
            <li
              key={publicKey}
              style={{
                border: "1px solid #333", padding: "15px", marginBottom: "15px", borderRadius: "5px", backgroundColor: "#333",
                width: "90vw"
              }}
            >
              <p><strong>Name:</strong> {name}</p>
              <p style={{ wordWrap: "break-word", width: "100%" }}>
    <strong>Public Key:</strong> {publicKey}
  </p>
              <p><strong>Status: </strong>
                <span style={{
                  color: status === "active" ? "#4CAF50" : "#F44336", fontWeight: "bold"
                }}>
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </span>
              </p>
              <div style={{ display: "flex", gap: "10px" ,flexWrap:"wrap",justifyContent:"flex-end"}}>
                <button
                  onClick={() => toggleStatus(publicKey, status)}
                  style={{
                    padding: "5px 10px", backgroundColor: "white", color: "black", border: "none", borderRadius: "5px",
                    cursor: "pointer",marginTop:"10px"
                  }}
                >
                  Toggle Status
                </button>
                <button
                  onClick={() => getPrivateKey(publicKey, encryptedPrivateKey)}
                  style={{
                    padding: "5px 10px", backgroundColor: "white", color: "black", border: "none", borderRadius: "5px",
                    cursor: "pointer",marginTop:"10px"
                  }}
                >
                  Retrieve Private Key
                </button>
                <button
                  onClick={() => signMessage(publicKey, encryptedPrivateKey)}
                  style={{
                    padding: "5px 10px", backgroundColor: "white", color: "black", border: "none", borderRadius: "5px",
                    cursor: "pointer",marginTop:"10px"
                  }}
                >
                  Sign Message
                </button>
                <button
                  onClick={() => deleteKeyFromDB(publicKey)}
                  style={{
                    padding: "5px 10px", backgroundColor: "white", color: "black", border: "none", borderRadius: "5px",
                    cursor: "pointer", marginTop:"10px"
                  }}
                >
                  Delete Key
                </button>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p style={{ color: "#fff" }}>No keys available.</p>
      )}
    </div>
  );
};

export default App;
