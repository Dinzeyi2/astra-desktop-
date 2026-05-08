/**
 * Astra Desktop Proxy
 * ====================
 * Local proxy on 127.0.0.1:8877
 * Intercepts all AI traffic on the device.
 * Calls app.codeastra.dev to tokenize/resolve — same API as the SDK.
 *
 * Outgoing: intercept → tokenize via app.codeastra.dev → forward to AI
 * Incoming: intercept → resolve via app.codeastra.dev → return to user
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

const ASTRA_BASE = "https://app.codeastra.dev";

function getApiKey() {
  return store.get('api_key', '');
}

// ── AI hosts to intercept ─────────────────────────────────────────────────────
const AI_HOSTS = [
  'api.openai.com',
  'chatgpt.com', 'chat.openai.com',
  'api.anthropic.com', 'claude.ai',
  'generativelanguage.googleapis.com', 'gemini.google.com',
  'copilot.microsoft.com', 'sydney.bing.com',
  'api.perplexity.ai', 'perplexity.ai',
  'api.mistral.ai', 'api.cohere.ai',
  'api.together.xyz', 'api.groq.com',
];

function isAIHost(hostname) {
  return AI_HOSTS.some(h => hostname === h || hostname.endsWith('.' + h));
}

// ── Astra API calls ───────────────────────────────────────────────────────────

async function astraProtect(text) {
  const key = getApiKey();
  if (!key) return { protected_text: text, count: 0, entities: [] };
  try {
    const res = await fetch(`${ASTRA_BASE}/protect/text`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
      body:    JSON.stringify({ text }),
      timeout: 5000,
    });
    if (!res.ok) return { protected_text: text, count: 0, entities: [] };
    return await res.json();
  } catch (_) {
    return { protected_text: text, count: 0, entities: [] };
  }
}

async function astraResolveBatch(tokens) {
  const key = getApiKey();
  if (!key || !tokens.length) return {};
  try {
    const res = await fetch(`${ASTRA_BASE}/vault/resolve-batch`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
      body:    JSON.stringify({ tokens }),
      timeout: 5000,
    });
    if (!res.ok) return {};
    const data = await res.json();
    return data.resolved || {};
  } catch (_) {
    return {};
  }
}

// ── Build system prompt from entities ────────────────────────────────────────

function buildSystemPrompt(entities) {
  if (!entities?.length) return '';
  const lines = [
    'ASTRA ZERO TRUST CONTEXT:',
    'The following tokens are transparent aliases for sensitive data.',
    'Treat each token exactly like the real value it represents.',
    'Use them directly in all actions. The system resolves automatically.',
    'Do NOT mention tokens, privacy, or protection in your response.',
    'Just act as if you have the real values and complete the task.',
    '',
  ];
  for (const e of entities) {
    if (e.token && e.type) {
      lines.push(`${e.token} = ${e.type.toLowerCase()} — use directly in actions`);
    }
  }
  return lines.join('\n');
}

// ── Process outgoing request body ─────────────────────────────────────────────

const TOKEN_RE = /\[CVT:[A-Z]+:[A-F0-9]+\]/g;

async function processOutgoing(bodyStr, hostname) {
  if (!bodyStr?.trim()) return { body: bodyStr, count: 0 };

  let parsed;
  try { parsed = JSON.parse(bodyStr); } catch (_) { return { body: bodyStr, count: 0 }; }

  // Chat completion format
  if (!parsed?.messages || !Array.isArray(parsed.messages)) {
    return { body: bodyStr, count: 0 };
  }

  // Collect all text from user messages
  const userMessages = parsed.messages.filter(m => m.role === 'user');
  const allText      = userMessages.map(m =>
    typeof m.content === 'string' ? m.content :
    Array.isArray(m.content) ? m.content.filter(c => c.type === 'text').map(c => c.text).join(' ') : ''
  ).join('\n');

  if (!allText.trim()) return { body: bodyStr, count: 0 };

  // Call app.codeastra.dev to protect
  const result = await astraProtect(allText);
  if (!result.count || result.count === 0) return { body: bodyStr, count: 0 };

  // Build token map: original → token
  const tokenMap = {};
  for (const e of (result.entities || [])) {
    if (e.original && e.token) tokenMap[e.original] = e.token;
  }

  // Replace real values in all messages
  parsed.messages = parsed.messages.map(msg => {
    if (msg.role === 'system') return msg;
    let content = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
    for (const [real, token] of Object.entries(tokenMap)) {
      content = content.replaceAll(real, token);
    }
    return { ...msg, content };
  });

  // Inject system prompt
  const systemPrompt = buildSystemPrompt(result.entities);
  const existingSystem = parsed.messages.find(m => m.role === 'system');
  if (existingSystem) {
    existingSystem.content = systemPrompt + '\n\n' + existingSystem.content;
  } else {
    parsed.messages = [{ role: 'system', content: systemPrompt }, ...parsed.messages];
  }

  logIntercept(hostname, result.count);

  console.log(`[Astra Proxy] Protected ${result.count} values → ${hostname}`);
  return { body: JSON.stringify(parsed), count: result.count };
}

// ── Process incoming response body ────────────────────────────────────────────

async function processIncoming(bodyStr) {
  if (!bodyStr) return bodyStr;
  TOKEN_RE.lastIndex = 0;
  if (!TOKEN_RE.test(bodyStr)) return bodyStr;

  const tokens = [...new Set(bodyStr.match(/\[CVT:[A-Z]+:[A-F0-9]+\]/g) || [])];
  if (!tokens.length) return bodyStr;

  const resolved = await astraResolveBatch(tokens);
  if (!Object.keys(resolved).length) return bodyStr;

  let result = bodyStr;
  for (const [token, real] of Object.entries(resolved)) {
    if (real) result = result.replaceAll(token, real);
  }
  return result;
}

// ── Proxy server ──────────────────────────────────────────────────────────────

let proxyServer = null;
let _caCert = null, _caKey = null;

function setCA(cert, key) {
  _caCert = cert;
  _caKey  = key;
}

async function startProxy(port, caCert, caKey) {
  if (caCert) { _caCert = caCert; _caKey = caKey; }

  proxyServer = http.createServer(async (req, res) => {
    const parsed   = url.parse(req.url);
    const hostname = parsed.hostname || (req.headers.host || '').split(':')[0];

    if (!isAIHost(hostname)) {
      return passthrough(req, res);
    }

    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', async () => {
      try {
        const { body: processed, count } = await processOutgoing(body, hostname);

        const options = {
          hostname,
          port:    parsed.port || 80,
          path:    parsed.path || '/',
          method:  req.method,
          headers: { ...req.headers, 'content-length': Buffer.byteLength(processed || body) },
        };

        const proxyReq = http.request(options, proxyRes => {
          let responseBody = '';
          proxyRes.on('data', c => { responseBody += c.toString(); });
          proxyRes.on('end', async () => {
            const final = await processIncoming(responseBody);
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            res.end(final);
          });
        });

        proxyReq.on('error', err => { res.writeHead(502); res.end(err.message); });
        proxyReq.write(processed || body);
        proxyReq.end();
      } catch (err) {
        res.writeHead(500); res.end(err.message);
      }
    });
  });

  // HTTPS CONNECT
  proxyServer.on('connect', (req, clientSocket, head) => {
    const [hostname, portStr] = req.url.split(':');
    const port = parseInt(portStr) || 443;

    if (!isAIHost(hostname)) {
      // Pass through
      const serverSocket = net.connect(port, hostname, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        serverSocket.write(head);
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
      });
      serverSocket.on('error', () => clientSocket.destroy());
      return;
    }

    // Intercept HTTPS for AI hosts
    if (!_caCert || !_caKey) {
      // No cert — pass through without interception
      const serverSocket = net.connect(port, hostname, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        serverSocket.write(head);
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
      });
      serverSocket.on('error', () => clientSocket.destroy());
      return;
    }

    // Generate server cert for this hostname
    const { cert, key } = generateServerCert(hostname, _caCert, _caKey);

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    // TLS server to intercept client connection
    const tlsServer = tls.createServer({ cert, key }, tlsClientSocket => {
      let requestData = '';

      tlsClientSocket.on('data', chunk => { requestData += chunk.toString(); });

      tlsClientSocket.on('end', async () => {
        if (!requestData) return;

        // Parse body from HTTP over TLS
        const headerEnd = requestData.indexOf('\r\n\r\n');
        const body      = headerEnd !== -1 ? requestData.slice(headerEnd + 4) : requestData;
        const headers   = headerEnd !== -1 ? requestData.slice(0, headerEnd) : '';

        try {
          const { body: processed } = await processOutgoing(body, hostname);

          // Connect to real server
          const tlsServerSocket = tls.connect({
            host: hostname, port, servername: hostname, rejectUnauthorized: true,
          }, () => {
            // Rebuild request with processed body
            const contentLength = Buffer.byteLength(processed || body);
            const newHeaders    = headers.replace(
              /content-length:\s*\d+/i,
              `Content-Length: ${contentLength}`
            );
            tlsServerSocket.write(`${newHeaders}\r\n\r\n`);
            tlsServerSocket.write(processed || body);
          });

          let responseData = '';
          tlsServerSocket.on('data', c => { responseData += c.toString(); });
          tlsServerSocket.on('end', async () => {
            const final = await processIncoming(responseData);
            tlsClientSocket.write(final);
            tlsClientSocket.end();
          });

          tlsServerSocket.on('error', () => tlsClientSocket.destroy());
        } catch (err) {
          tlsClientSocket.write(`HTTP/1.1 500 Internal Server Error\r\n\r\n${err.message}`);
          tlsClientSocket.end();
        }
      });
    });

    tlsServer.on('error', () => clientSocket.destroy());
    tlsServer.emit('connection', clientSocket);
  });

  return new Promise((resolve, reject) => {
    proxyServer.listen(port, '127.0.0.1', () => {
      console.log(`[Astra Proxy] Listening on 127.0.0.1:${port} → routing through app.codeastra.dev`);
      resolve();
    });
    proxyServer.on('error', reject);
  });
}

async function stopProxy() {
  if (proxyServer) { proxyServer.close(); proxyServer = null; }
}

function passthrough(req, res) {
  const parsed  = url.parse(req.url);
  const options = {
    hostname: parsed.hostname, port: parsed.port || 80,
    path: parsed.path, method: req.method, headers: req.headers,
  };
  const proxyReq = http.request(options, proxyRes => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });
  proxyReq.on('error', () => res.end());
  req.pipe(proxyReq);
}

module.exports = { startProxy, stopProxy, setCA };
