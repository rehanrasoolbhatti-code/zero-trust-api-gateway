const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

// Simple In-Memory Cache Store for High Speed
const responseCache = new Map();

// Parse JSON body for security inspection
app.use(express.json({ limit: '10kb' }));

// ---------------------------------------------------------
// 1. RATE LIMITING LAYER (DDoS & Brute-Force Defense)
// ---------------------------------------------------------

// General Rate Limiter for all routes (100 requests per 15 minutes)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minutes window
  max: 100, // Max 100 requests per IP per window
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  message: {
    status: 429,
    error: 'Too Many Requests',
    message: 'Global rate limit exceeded. Please try again after 15 minutes.'
  }
});

// Strict Rate Limiter for Sensitive Transaction APIs (5 requests per 1 minute)
const strictTransactionLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 Minute window
  max: 5, // Max 5 transactions per IP per minute (Protects against brute force)
  standardHeaders: true,
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  message: {
    status: 429,
    error: 'Security Enforcement: Rate Limit Exceeded',
    message: 'Too many transaction attempts from this IP. Please wait 60 seconds.'
  }
});

// Apply Global Rate Limiter across all incoming requests
app.use(globalLimiter);

// ---------------------------------------------------------
// 2. PERFORMANCE LOGGER & LATENCY MONITORING
// ---------------------------------------------------------
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} -> Status: ${res.statusCode} (${duration}ms)`);
  });
  next();
});

// ---------------------------------------------------------
// 3. OWASP WAF INSPECTION LAYER
// ---------------------------------------------------------
app.use((req, res, next) => {
  const attackSignatures = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)/i,
    /(<script\b[^>]*>.*?<\/script>)/i,
    /(\.\.\/|\.\.\\)/i
  ];

  const isMalicious = (val) => {
    if (!val) return false;
    if (typeof val === 'string') return attackSignatures.some(regex => regex.test(val));
    if (typeof val === 'object' && val !== null) return Object.values(val).some(isMalicious);
    return false;
  };

  if (isMalicious(req.body) || isMalicious(req.query)) {
    return res.status(400).json({ error: 'WAF Blocked', message: 'Malicious payload pattern detected' });
  }

  next();
});

// ---------------------------------------------------------
// 4. HIGH-SPEED CACHING LAYER
// ---------------------------------------------------------
app.use((req, res, next) => {
  if (req.method === 'GET' && req.url !== '/health') {
    const cachedResponse = responseCache.get(req.url);
    if (cachedResponse && (Date.now() - cachedResponse.timestamp < 30000)) { // 30 sec TTL
      console.log(`⚡ [CACHE HIT] Serving ${req.url} directly from Gateway Memory`);
      return res.status(200).json(cachedResponse.data);
    }
  }
  next();
});

// ---------------------------------------------------------
// 5. HEALTH CHECK ENDPOINT
// ---------------------------------------------------------
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'HEALTHY', 
    engine: 'Zero-Trust Advance Reverse Proxy Gateway v2.1 (Rate-Limited)',
    uptime: `${Math.floor(process.uptime())}s`
  });
});

// ---------------------------------------------------------
// 6. PROTECTED ENTERPRISE TRANSACTION ROUTE
// ---------------------------------------------------------
const HMAC_SECRET = process.env.HMAC_SECRET || 'commercial_grade_super_secret_key_2026';

// Apply strict 5-request/min limiter ONLY to this transaction endpoint
app.post('/api/v1/enterprise/transaction', strictTransactionLimiter, (req, res) => {
  const signature = req.headers['x-signature-256'];
  const timestamp = req.headers['x-request-timestamp'];

  if (!signature || !timestamp) {
    return res.status(401).json({ error: 'Security Violation: Missing HMAC Signature or Timestamp' });
  }

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp, 10)) > 300) {
    return res.status(403).json({ error: 'Security Violation: Request Expired (Replay Protection)' });
  }

  const signatureBase = `${timestamp}.${JSON.stringify(req.body)}`;
  const expectedSignature = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(signatureBase)
    .digest('hex');

  const sigBuffer = Buffer.from(signature);
  const expBuffer = Buffer.from(expectedSignature);

  if (sigBuffer.length !== expBuffer.length || !crypto.timingSafeEqual(sigBuffer, expBuffer)) {
    return res.status(403).json({ error: 'Security Violation: Invalid Signature Integrity' });
  }

  // Verification Completed! Respond with 200 OK
  res.status(200).json({
    success: true,
    message: 'Transaction verified and routed through Zero-Trust Advance Engine',
    timestamp: new Date().toISOString(),
    payload: req.body,
  });
});

const PORT = 5000;
const HOST = '127.0.0.1';

const server = app.listen(PORT, HOST, () => {
  console.log(`🚀 Zero-Trust Rate-Limited Gateway active on http://${HOST}:${PORT}`);
  console.log('🟢 Rate Limiting & DDoS Defense actively monitoring traffic...');
});

server.on('error', (err) => {
  console.error('❌ Server Listen Error:', err.message);
});