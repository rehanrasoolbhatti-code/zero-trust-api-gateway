const http = require('http');

console.log('⚡ Sending 7 Rapid Requests to Test Rate Limiter Block...\n');

for (let i = 1; i <= 7; i++) {
  setTimeout(() => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: 5000,
      path: '/api/v1/enterprise/transaction',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        console.log(`Request #${i} -> HTTP Status: ${res.statusCode} | Response: ${data}`);
      });
    });

    req.write(JSON.stringify({ amount: 100 }));
    req.end();
  }, i * 200); // Send request every 200ms
}