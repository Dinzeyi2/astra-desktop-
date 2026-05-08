/**
 * Astra Desktop Vault
 * ====================
 * No local vault needed — app.codeastra.dev handles everything.
 * This module only handles local stats and audit logging.
 */
'use strict';

const Store = require('electron-store');
const store = new Store();

function logIntercept(hostname, count) {
  const today = new Date().toISOString().split('T')[0];
  const log   = store.get('audit_log', []);

  log.unshift({ hostname, count, timestamp: Date.now() });
  if (log.length > 200) log.splice(200);
  store.set('audit_log', log);

  // Daily stats
  const stats = store.get('stats', {});
  stats[today] = (stats[today] || 0) + count;
  store.set('stats', stats);
}

function getAuditLog(limit = 50) {
  return store.get('audit_log', []).slice(0, limit);
}

function getStats() {
  const stats = store.get('stats', {});
  const today = new Date().toISOString().split('T')[0];
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  return { today: stats[today] || 0, total };
}

function resetStats() {
  store.set('stats', {});
  store.set('audit_log', []);
}

module.exports = { logIntercept, getAuditLog, getStats, resetStats };
