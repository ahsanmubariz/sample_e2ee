const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// In-memory storage for users and their public keys
const users = new Map();

// Register a new user
app.post('/register', (req, res) => {
  const { username, publicKey } = req.body;

  if (!username || !publicKey) {
    return res.status(400).json({ error: 'Username and public key are required' });
  }

  if (users.has(username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  // Store the user's public key
  users.set(username, { publicKey, messages: [] });

  console.log(`User ${username} registered`);
  res.json({ message: 'Registration successful' });
});

// Get a user's public key
app.get('/public-key/:username', (req, res) => {
  const username = req.params.username;

  if (!users.has(username)) {
    return res.status(404).json({ error: 'User not found' });
  }

  const publicKey = users.get(username).publicKey;
  res.json({ publicKey });
});

// Send an encrypted message to a user
app.post('/send-message', (req, res) => {
  const { senderUsername, targetUsername, ciphertext, iv } = req.body;

  if (!senderUsername || !targetUsername || !ciphertext || !iv) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (!users.has(targetUsername)) {
    return res.status(404).json({ error: 'Target user not found' });
  }

  // Store the message for the target user
  const targetUser = users.get(targetUsername);
  targetUser.messages.push({ senderUsername, ciphertext, iv });

  console.log(`Message sent from ${senderUsername} to ${targetUsername}`);
  res.json({ message: 'Message sent successfully' });
});

// Get messages for a user
app.get('/messages/:username', (req, res) => {
  const username = req.params.username;

  if (!users.has(username)) {
    return res.status(404).json({ error: 'User not found' });
  }

  const userMessages = users.get(username).messages;
  res.json({ messages: userMessages });

  // Clear the messages after retrieving them
  users.get(username).messages = [];
});

// Start the server
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});