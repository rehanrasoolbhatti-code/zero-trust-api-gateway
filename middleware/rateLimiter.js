const requests = new Map();

module.exports = function rateLimiter(limit = 100, windowInSec = 10) {
  return (req, res, next) => {
    try {
      const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
      const now = Date.now();
      const windowMs = windowInSec * 1000;

      if (!requests.has(ip)) {
        requests.set(ip, []);
      }

      const timestamps = requests.get(ip).filter(ts => now - ts < windowMs);
      timestamps.push(now);
      requests.set(ip, timestamps);

      if (timestamps.length > limit) {
        return res.status(429).json({ error: 'Rate limit exceeded. Try again later.' });
      }

      next();
    } catch (err) {
      console.error('Rate Limiter Error:', err.message);
      next();
    }
  };
};