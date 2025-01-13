import { useState, useEffect } from 'react';

export default function Home() {
  const [username, setUsername] = useState('');
  const [publicKey, setPublicKey] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);
  const [peerPublicKey, setPeerPublicKey] = useState(null);
  const [sharedSecret, setSharedSecret] = useState(null);
  const [message, setMessage] = useState('');
  const [receivedMessages, setReceivedMessages] = useState([]);
  const [targetUsername, setTargetUsername] = useState('');

  // Register the user with WebAuthn
  const registerWithWebAuthn = async () => {
    if (!username) {
      console.error("Username is required");
      return;
    }

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: {
          name: "E2EE Example",
        },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: username,
          displayName: username,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ES256 (ECDSA with SHA-256)
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
        },
        timeout: 60000,
        attestation: "direct",
      },
    });

    console.log("WebAuthn Credential:", credential);

    // Generate an ECDH key pair for encryption
    const ecdhKeyPair = await generateECDHKeyPair();
    const exportedPublicKey = await crypto.subtle.exportKey("spki", ecdhKeyPair.publicKey);
    const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8", ecdhKeyPair.privateKey);

    setPublicKey(exportedPublicKey);
    setPrivateKey(exportedPrivateKey);

    console.log("ECDH Public Key:", exportedPublicKey);
    console.log("ECDH Private Key:", exportedPrivateKey);

    // Send the username and public key to the server
    const response = await fetch('http://localhost:3001/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        publicKey: Array.from(new Uint8Array(exportedPublicKey)),
      }),
    });

    const data = await response.json();
    console.log(data.message);
  };

  // Get the target user's public key
  const getPeerPublicKey = async () => {
    if (!targetUsername) {
      console.error("Target username is required");
      return;
    }

    const response = await fetch(`http://localhost:3001/public-key/${targetUsername}`);
    const data = await response.json();

    if (data.error) {
      console.error(data.error);
      return;
    }

    // Convert the public key to Uint8Array
    const peerPublicKey = new Uint8Array(data.publicKey);
    setPeerPublicKey(peerPublicKey);

    console.log(`Received Peer Public Key from ${targetUsername}:`, peerPublicKey);

    // Derive shared secret if private key is available
    if (privateKey) {
      try {
        const secret = await deriveSharedSecret(privateKey, peerPublicKey);
        setSharedSecret(secret);
        console.log("Shared Secret Derived:", secret);
      } catch (error) {
        console.error("Error deriving shared secret:", error);
      }
    } else {
      console.error("Private key is missing");
    }
  };

  // Send an encrypted message to the target user
  const sendEncryptedMessage = async () => {
    if (!sharedSecret || !targetUsername) {
      console.error("Shared secret or target username is missing");
      return;
    }

    const derivedKey = await deriveKey(sharedSecret, new Uint8Array(16)); // Use a fixed salt for simplicity
    const { ciphertext, iv } = await encryptMessage(derivedKey, message);

    const response = await fetch('http://localhost:3001/send-message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        senderUsername: username,
        targetUsername,
        ciphertext: Array.from(new Uint8Array(ciphertext)),
        iv: Array.from(iv),
      }),
    });

    const data = await response.json();
    console.log(data.message);

    setMessage('');
  };

  // Poll for new messages
  useEffect(() => {
    const pollMessages = async () => {
      if (!username || !sharedSecret) return;

      const response = await fetch(`http://localhost:3001/messages/${username}`);
      const data = await response.json();

      if (data.error) {
        console.error(data.error);
        return;
      }

      if (data.messages.length > 0) {
        for (const msg of data.messages) {
          try {
            const derivedKey = await deriveKey(sharedSecret, new Uint8Array(16));
            const decryptedMessage = await decryptMessage(
              derivedKey,
              new Uint8Array(msg.ciphertext),
              new Uint8Array(msg.iv)
            );
            console.log(`Decrypted Message from ${msg.senderUsername}:`, decryptedMessage);
            setReceivedMessages((prev) => [...prev, { sender: msg.senderUsername, message: decryptedMessage }]);
          } catch (error) {
            console.error("Error decrypting message:", error);
          }
        }
      }
    };

    const interval = setInterval(pollMessages, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, [username, sharedSecret]);

  // Generate an ECDH key pair
  const generateECDHKeyPair = async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );

    return keyPair;
  };

  // ECDH Key Exchange
  const deriveSharedSecret = async (privateKey, peerPublicKey) => {
    // Import the private key
    const privateKeyObj = await crypto.subtle.importKey(
      "pkcs8",
      privateKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
    );

    // Import the peer's public key
    const publicKeyObj = await crypto.subtle.importKey(
      "spki",
      peerPublicKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    // Derive the shared secret
    const sharedSecret = await crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKeyObj },
      privateKeyObj,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    return sharedSecret;
  };

  // HKDF for Key Derivation
  const deriveKey = async (sharedSecret, salt) => {
    const keyMaterial = await crypto.subtle.exportKey("raw", sharedSecret);
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        salt: salt,
        info: new Uint8Array(),
        hash: "SHA-256",
      },
      await crypto.subtle.importKey("raw", keyMaterial, "HKDF", false, ["deriveKey"]),
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    return derivedKey;
  };

  // Encrypt Message
  const encryptMessage = async (key, message) => {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM
    const encodedMessage = new TextEncoder().encode(message);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encodedMessage
    );

    return { ciphertext, iv };
  };

  // Decrypt Message
  const decryptMessage = async (key, ciphertext, iv) => {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  };

  return (
    <div>
      <h1>End-to-End Encryption with WebAuthn</h1>
      <div>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Enter your username"
        />
        <button onClick={registerWithWebAuthn}>Register with WebAuthn</button>
      </div>
      <div>
        <input
          type="text"
          value={targetUsername}
          onChange={(e) => setTargetUsername(e.target.value)}
          placeholder="Enter target username"
        />
        <button onClick={getPeerPublicKey}>Get Peer Public Key</button>
      </div>
      <div>
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Type a message"
        />
        <button onClick={sendEncryptedMessage}>Send Encrypted Message</button>
      </div>
      <h2>Received Messages:</h2>
      <ul>
        {receivedMessages.map((msg, index) => (
          <li key={index}>
            <strong>{msg.sender}:</strong> {msg.message}
          </li>
        ))}
      </ul>
    </div>
  );
}