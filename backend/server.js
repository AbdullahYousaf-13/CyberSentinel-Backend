require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Test Route
app.get('/', (req, res) => {
    res.send('CyberSentinel Backend is Running!');
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});