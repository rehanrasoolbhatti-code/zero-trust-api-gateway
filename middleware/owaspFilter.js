module.exports = function owaspFilter(req, res, next) {
  try {
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
  } catch (err) {
    console.error('WAF Middleware Error:', err.message);
    next();
  }
};