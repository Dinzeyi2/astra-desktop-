/**
 * Astra Desktop Proxy v2
 * Calls app.codeastra.dev for tokenization and resolution.
 */
'use strict';

const http  = require('http');
const https = require('https');
const net   = require('net');
const tls   = require('tls');
const url   = require('url');
const fetch = require('node-fetch');
const Store = require('electron-store');
const { generateServerCert } = require('./cert-installer');
const { logIntercept } = require('../vault/vault');

const store = new Store();
const ASTRA = 'https://app.codeastra.dev';

function getKey() { return store.get('api_key', ''); }
function setApiKey(k) { store.set('api_key', k); }

const AI_HOSTS = [
  'api.openai.com','chatgpt.com','chat.openai.com',
  'api.anthropic.com','claude.ai',
  'generativelanguage.googleapis.com','gemini.google.com',
  'copilot.microsoft.com','sydney.bing.com',
  'api.perplexity.ai','perplexity.ai',
  'api.mistral.ai','api.cohere.ai','api.groq.com',
];

function isAI(host) {
  return AI_HOSTS.some(h => host === h || host.endsWith('.' + h));
}

const TOKEN_RE = /\[CVT:[A-Z]+:[A-F0-9]+\]/g;

async function astraProtect(text) {
  const key = getKey();
  if (!key) return { protected_text: text, count: 0, entities: [] };
  try {
    const r = await fetch(`${ASTRA}/protect/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
      body: JSON.stringify({ text }),
      timeout: 5000,
    });
    return r.ok ? await r.json() : { protected_text: text, count: 0, entities: [] };
  } catch (_) { return { protected_text: text, count: 0, entities: [] }; }
}

async function astraResolve(tokens) {
  const key = getKey();
  if (!key || !tokens.length) return {};
  try {
    const r = await fetch(`${ASTRA}/vault/resolve-batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
      body: JSON.stringify({ tokens }),
      timeout: 5000,
    });
    if (!r.ok) return {};
    const d = await r.json();
    return d.resolved || {};
  } catch (_) { return {}; }
}

function buildSystemPrompt(entities) {
  if (!entities?.length) return '';
  const lines = [
    'ASTRA ZERO TRUST CONTEXT:',
    'These tokens are transparent aliases. Treat them as real values.',
    'Use them directly in all actions. Do NOT mention tokens or privacy.',
    'Just complete the task as if you have the real values.',
    '',
    ...entities.map(e => `${e.token} = ${(e.type||'').toLowerCase()} — use directly`),
  ];
  return lines.join('\n');
}

async function processOut(body, host) {
  if (!body?.trim()) return { body, count: 0 };
  let parsed;
  try { parsed = JSON.parse(body); } catch (_) { return { body, count: 0 }; }
  if (!Array.isArray(parsed?.messages)) return { body, count: 0 };

  const text = parsed.messages
    .filter(m => m.role === 'user')
    .map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content))
    .join('\n');

  if (!text.trim()) return { body, count: 0 };

  const result = await astraProtect(text);
  if (!result.count) return { body, count: 0 };

  // Build replacement map
  const map = {};
  for (const e of (result.entities || [])) {
    if (e.original && e.token) map[e.original] = e.token;
  }

  // Replace in messages
  parsed.messages = parsed.messages.map(m => {
    if (m.role === 'system') return m;
    let c = typeof m.content === 'string' ? m.content : JSON.stringify(m.content);
    for (const [real, tok] of Object.entries(map)) c = c.replaceAll(real, tok);
    return { ...m, content: c };
  });

  // Inject system prompt
  const sp = buildSystemPrompt(result.entities);
  const ex = parsed.messages.find(m => m.role === 'system');
  if (ex) ex.content = sp + '\n\n' + ex.content;
  else    parsed.messages = [{ role: 'system', content: sp }, ...parsed.messages];

  logIntercept(host, result.count);
  console.log(`[Astra] Protected ${result.count} values → ${host}`);
  return { body: JSON.stringify(parsed), count: result.count };
}

async function processIn(body) {
  TOKEN_RE.lastIndex = 0;
  if (!TOKEN_RE.test(body || '')) return body;
  const tokens = [...new Set((body.match(/\[CVT:[A-Z]+:[A-F0-9]+\]/g) || []))];
  if (!tokens.length) return body;
  const resolved = await astraResolve(tokens);
  let result = body;
  for (const [t, v] of Object.entries(resolved)) if (v) result = result.replaceAll(t, v);
  return result;
}

let _ca = null, _caKey = null;
function setCA(cert, key) { _ca = cert; _caKey = key; }

let srv = null;

async function startProxy(port, caCert, caKey) {
  if (caCert) { _ca = caCert; _caKey = caKey; }

  srv = http.createServer(async (req, res) => {
    const parsed = url.parse(req.url);
    const host   = parsed.hostname || (req.headers.host || '').split(':')[0];
    if (!isAI(host)) return passthrough(req, res);

    let body = '';
    req.on('data', c => { body += c.toString(); });
    req.on('end', async () => {
      try {
        const { body: out } = await processOut(body, host);
        const opts = {
          hostname: host, port: parsed.port || 80,
          path: parsed.path || '/', method: req.method,
          headers: { ...req.headers, 'content-length': Buffer.byteLength(out || body) },
        };
        const pr = http.request(opts, proxyRes => {
          let rb = '';
          proxyRes.on('data', c => { rb += c.toString(); });
          proxyRes.on('end', async () => {
            const final = await processIn(rb);
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            res.end(final);
          });
        });
        pr.on('error', e => { res.writeHead(502); res.end(e.message); });
        pr.write(out || body);
        pr.end();
      } catch (e) { res.writeHead(500); res.end(e.message); }
    });
  });

  // HTTPS CONNECT tunnel
  srv.on('connect', (req, sock, head) => {
    const [host, portStr] = req.url.split(':');
    const port = parseInt(portStr) || 443;

    if (!isAI(host) || !_ca) {
      // Pass through
      const s = net.connect(port, host, () => {
        sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        s.write(head); s.pipe(sock); sock.pipe(s);
      });
      s.on('error', () => sock.destroy());
      return;
    }

    // Intercept with TLS
    const { cert, key } = generateServerCert(host, _ca, _caKey);
    sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    const tlsSrv = tls.createServer({ cert, key }, tlsSock => {
      let data = '';
      tlsSock.on('data', c => { data += c.toString(); });
      tlsSock.on('end', async () => {
        if (!data) return;
        const hi = data.indexOf('\r\n\r\n');
        const body = hi !== -1 ? data.slice(hi + 4) : data;
        try {
          const { body: out } = await processOut(body, host);
          const remote = tls.connect({ host, port, servername: host, rejectUnauthorized: true }, () => {
            const cl = Buffer.byteLength(out || body);
            const hdr = (hi !== -1 ? data.slice(0, hi) : '').replace(/content-length:\s*\d+/i, `Content-Length: ${cl}`);
            remote.write(`${hdr}\r\n\r\n`);
            remote.write(out || body);
          });
          let rb = '';
          remote.on('data', c => { rb += c.toString(); });
          remote.on('end', async () => {
            const final = await processIn(rb);
            tlsSock.write(final);
            tlsSock.end();
          });
          remote.on('error', () => tlsSock.destroy());
        } catch (e) {
          tlsSock.write(`HTTP/1.1 500 Error\r\n\r\n${e.message}`);
          tlsSock.end();
        }
      });
    });
    tlsSrv.on('error', () => sock.destroy());
    tlsSrv.emit('connection', sock);
  });

  return new Promise((resolve, reject) => {
    srv.listen(port, '127.0.0.1', () => {
      console.log(`[Astra Proxy] Listening on 127.0.0.1:${port} → routing through app.codeastra.dev`);
      resolve();
    });
    srv.on('error', reject);
  });
}

async function stopProxy() {
  if (srv) { srv.close(); srv = null; }
}

function passthrough(req, res) {
  const p    = url.parse(req.url);
  const opts = { hostname: p.hostname, port: p.port || 80, path: p.path, method: req.method, headers: req.headers };
  const pr   = http.request(opts, pr2 => { res.writeHead(pr2.statusCode, pr2.headers); pr2.pipe(res); });
  pr.on('error', () => res.end());
  req.pipe(pr);
}

module.exports = { startProxy, stopProxy, setCA, setApiKey };
