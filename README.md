# BotShield Middleware

An Economic Deterrence Bot Mitigation Middleware for Express/Node.js based on V8 Javascript cryptographic token challenges. 

This package protects your valuable API endpoints by filtering out automated scrapers and bots trying to steal data, while allowing legitimate human browsers to seamlessly access the content.

## Installation

```bash
npm install bot-shield
```

## Basic Usage

```javascript
const express = require('express');
const BotShield = require('bot-shield');

const app = express();
const botShield = new BotShield({
    riskThreshold: 70,              // Blocking threshold (default 70)
    maxRequestsPerWindow: 50,       // Rate limiting volume
    minTimeBetweenRequestsMs: 200   // Velocity tracking
});

// 1. Expose the challenge token endpoint
app.get('/api/bot-challenge', botShield.challengeEndpoint);

// 2. Protect your valuable data API with the middleware
app.get('/api/data', botShield.protectApi, (req, res) => {
    res.json({ message: "Protected data payload!" });
});

app.listen(3000);
```

## Frontend Integration (The X-BOT-SIGNAL)

Legitimate browsers must solve the execution challenge to retrieve the token and present it in the headers (`X-shield-token`) to access the protected JSON payload.

```javascript
// Step 1: Challenge
const challenge = await fetch('http://localhost:3000/api/bot-challenge');
const { token } = await challenge.json();

// Step 2: Retrieve protected data
const response = await fetch('http://localhost:3000/api/data', {
    headers: {
        'x-shield-token': token
    }
});
const data = await response.json();
```
