const crypto = require('crypto');

class BotShield {
    constructor(options = {}) {
        this.riskThreshold = options.riskThreshold || 70;
        this.timeWindowMs = options.timeWindowMs || 60000; 
        this.maxRequestsPerWindow = options.maxRequestsPerWindow || 50;
        this.minTimeBetweenRequestsMs = options.minTimeBetweenRequestsMs || 200; 
        
        this.clients = new Map();
        this.validTokens = new Set();
    }

    challengeEndpoint = (req, res) => {
        const token = crypto.randomBytes(16).toString('hex');
        this.validTokens.add(token);
        setTimeout(() => this.validTokens.delete(token), 5 * 60 * 1000);
        res.json({ token });
    };

    _getClientData(ip) {
        if (!this.clients.has(ip)) {
            this.clients.set(ip, {
                requestCount: 0,
                lastRequestTime: Date.now(),
                firstRequestTime: Date.now()
            });
        }
        return this.clients.get(ip);
    }

    _calculateRiskScore(clientData, hasValidToken, timeSinceLastRequest) {
        let score = 0;
        const signals = {};

        if (!hasValidToken) {
            score += 75; 
            signals.jsExecuted = false;
        } else {
            signals.jsExecuted = true;
        }

        if (timeSinceLastRequest < this.minTimeBetweenRequestsMs) {
            score += 30;
            signals.suspiciousTiming = true;
        }

        if (clientData.requestCount > this.maxRequestsPerWindow) {
            score += 40;
            signals.highVolume = true;
        }

        return { score, signals };
    }

    protectApi = (req, res, next) => {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const clientToken = req.headers['x-shield-token'];
        const now = Date.now();

        const clientData = this._getClientData(ip);
        const timeSinceLastRequest = now - clientData.lastRequestTime;
        const hasValidToken = this.validTokens.has(clientToken);

        if (now - clientData.firstRequestTime > this.timeWindowMs) {
            clientData.requestCount = 0;
            clientData.firstRequestTime = now;
        }

        clientData.requestCount += 1;
        clientData.lastRequestTime = now;

        const { score, signals } = this._calculateRiskScore(clientData, hasValidToken, timeSinceLastRequest);

        if (score >= this.riskThreshold) {
            console.log("\n" + "X".repeat(60));
            console.log("🚨 [THREAT INTERCEPTED] 🚨");
            console.log(`[!] Target: ${req.originalUrl} | IP: ${ip} | Risk Score: ${score}/100`);
            console.log(`[!] Primary Reason: X-BOT-SIGNAL Missing`);
            console.log("X".repeat(60));

            return res.status(403).json({
                error: "Access Denied",
                code: "SHIELD_ERR",
                message: "Verification Required. Unverified client behavior detected."
            });
        }

        this.clients.set(ip, clientData);
        next();
    };
}

module.exports = BotShield;
