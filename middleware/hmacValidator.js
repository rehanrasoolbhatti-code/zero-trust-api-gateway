const crypto = require('crypto');

module.exports = function verifyHmacSignature(secret) {
  return (req, res, next) => {
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
      .createHmac('sha256', secret)
      .update(signatureBase)
      .digest('hex');

    // Safe comparison without timing attack crash
    const sigBuffer = Buffer.from(signature);
    const expBuffer = Buffer.from(expectedSignature);

    if (sigBuffer.length !== expBuffer.length || !crypto.timingSafeEqual(sigBuffer, expBuffer)) {
      return res.status(403).json({ error: 'Security Violation: Invalid Signature Integrity' });
    }

    next();
  };
};