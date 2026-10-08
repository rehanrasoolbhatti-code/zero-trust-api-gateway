const crypto = require('crypto');

const GATEWAY_URL = 'http://127.0.0.1:5000';
const HMAC_SECRET = 'commercial_grade_super_secret_key_2026';

function generateHmacHeader(payload, timestamp, secret) {
  const signatureBase = `${timestamp}.${JSON.stringify(payload)}`;
  return crypto
    .createHmac('sha256', secret)
    .update(signatureBase)
    .digest('hex');
}

// Fetch with Timeout Helper
async function fetchWithTimeout(url, options = {}, timeout = 3000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

async function runSecurityTests() {
  console.log('==================================================');
  console.log('🛡️  STARTING ZERO-TRUST GATEWAY SECURITY SUITE  🛡️');
  console.log('==================================================\n');

  // TEST 1: Health Check Endpoint
  try {
    const res = await fetchWithTimeout(`${GATEWAY_URL}/health`);
    const data = await res.json();
    console.log('✅ TEST 1 [HEALTH CHECK]:', res.status === 200 ? 'PASSED' : 'FAILED', data);
  } catch (err) {
    console.error('❌ TEST 1 FAILED: Gateway offline hai ya answer nahi de raha!');
    return;
  }

  // TEST 2: WAF SQL Injection Attack Simulation
  try {
    const maliciousPayload = { username: "admin' OR '1'='1", amount: 100 };
    const res = await fetchWithTimeout(`${GATEWAY_URL}/api/v1/enterprise/transaction`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(maliciousPayload)
    });
    const data = await res.json();
    console.log('✅ TEST 2 [WAF SQLi DEFENSE]:', res.status === 400 ? 'PASSED (Malicious Payload Blocked!)' : 'FAILED', data);
  } catch (err) {
    console.error('❌ TEST 2 ERROR:', err.message);
  }

  // TEST 3: Replay Attack (Expired Timestamp)
  try {
    const validPayload = { userId: 'usr_101', amount: 250 };
    const expiredTimestamp = Math.floor(Date.now() / 1000) - 600;
    const signature = generateHmacHeader(validPayload, expiredTimestamp, HMAC_SECRET);

    const res = await fetchWithTimeout(`${GATEWAY_URL}/api/v1/enterprise/transaction`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature-256': signature,
        'x-request-timestamp': expiredTimestamp.toString()
      },
      body: JSON.stringify(validPayload)
    });
    const data = await res.json();
    console.log('✅ TEST 3 [REPLAY ATTACK PREVENTION]:', res.status === 403 ? 'PASSED (Expired Request Rejected!)' : 'FAILED', data);
  } catch (err) {
    console.error('❌ TEST 3 ERROR:', err.message);
  }

  // TEST 4: Valid HMAC Request
  try {
    const validPayload = { userId: 'usr_101', amount: 250 };
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const signature = generateHmacHeader(validPayload, currentTimestamp, HMAC_SECRET);

    const res = await fetchWithTimeout(`${GATEWAY_URL}/api/v1/enterprise/transaction`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature-256': signature,
        'x-request-timestamp': currentTimestamp.toString()
      },
      body: JSON.stringify(validPayload)
    });
    const data = await res.json();
    console.log('✅ TEST 4 [VALID HMAC TRANSACTION]:', res.status === 200 ? 'PASSED' : `STATUS: ${res.status}`, data);
  } catch (err) {
    console.error('❌ TEST 4 ERROR:', err.message);
  }

  console.log('\n==================================================');
  console.log('🎯 SECURITY SUITE EXECUTION COMPLETED');
  console.log('==================================================');
}

runSecurityTests();