// Self-contained local HTTPS server for the v0.7 network test. Generates a
// self-signed cert, listens on 8762 (reached from the device via `adb reverse`),
// and replies with a known marker. The sandbox uses an all-trusting client, so no
// external network or trusted CA is needed — TLS plaintext still flows through
// Conscrypt's SSL_write/SSL_read, which the agent hooks.
import https from 'node:https';
import selfsigned from 'selfsigned';

const PORT = Number(process.env.ADH_TLS_PORT ?? 8762);
const RESPONSE = 'ADH_NET_RESPONSE_v1';
// selfsigned v5 generate() is async (returns a Promise).
const pems = await selfsigned.generate(
  [{ name: 'commonName', value: 'localhost' }],
  { days: 3650, keySize: 2048, algorithm: 'sha256' },
);

const server = https.createServer({ key: pems.private, cert: pems.cert }, (req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    console.error(`[tls] ${req.method} ${req.url} marker=${req.headers['x-idh-marker'] ?? ''} bodyLen=${body.length}`);
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(RESPONSE);
  });
});
server.listen(PORT, '127.0.0.1', () => console.error(`[tls] listening on 127.0.0.1:${PORT}`));
process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
