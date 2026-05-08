/**
 * Astra Desktop — Main Process
 * =============================
 * Electron app that:
 * 1. Starts a local HTTP/HTTPS proxy on port 8877
 * 2. Sets the system proxy to route all traffic through it
 * 3. Proxy intercepts requests to AI endpoints
 * 4. Tokenizes outgoing sensitive data
 * 5. Detokenizes incoming responses
 * 6. Shows tray icon with stats
 * 7. User installs, forgets about it — everything is automatic
 */

const { app, BrowserWindow, Tray, Menu, nativeImage, session, ipcMain, shell } = require('electron');
const path   = require('path');
const Store  = require('electron-store');
const { startProxy, stopProxy }   = require('./proxy/proxy');
const { setupCertificate, isCertInstalled, removeCert, generateCA } = require('./proxy/cert-installer');

// CA cert — generated once, persisted
let CA = null;
const { getStats, resetStats }    = require('./vault/vault');

const store = new Store();

let tray          = null;
let settingsWindow = null;
let proxyPort      = 8877;
let proxyRunning   = false;

// ── App lifecycle ─────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  // Hide from dock on Mac — tray-only app
  if (process.platform === "darwin") {
    app.dock.hide();
  }

  // Generate CA cert
  CA = generateCA();

  // First launch — install certificate
  const certInstalled = store.get('cert_installed', false) || isCertInstalled();
  if (!certInstalled) {
    const result = await setupCertificate(CA.certPem);
    if (result.installed) {
      store.set('cert_installed', true);
      console.log('[Astra] Certificate installed successfully');
    } else {
      console.log('[Astra] Certificate not installed — HTTPS interception limited');
    }
  }

  await initProxy();
  createTray();
  setupIPC();

  // Auto-start proxy on launch
  if (store.get('auto_start', true)) {
    await enableProxy();
  }
});

app.on('window-all-closed', (e) => {
  // Keep running in tray even when all windows closed
  e.preventDefault();
});

app.on('before-quit', async () => {
  await disableProxy();
});

// ── Proxy management ──────────────────────────────────────────────────────────

async function initProxy() {
  try {
    await startProxy(proxyPort);
    proxyRunning = true;
    console.log(`[Astra] Proxy started on port ${proxyPort}`);
  } catch (err) {
    console.error('[Astra] Proxy start failed:', err.message);
  }
}

async function enableProxy() {
  if (!proxyRunning) await initProxy();

  // Set system proxy — all apps route through Astra
  await session.defaultSession.setProxy({
    proxyRules: `http=127.0.0.1:${proxyPort};https=127.0.0.1:${proxyPort}`,
  });

  store.set('proxy_enabled', true);
  updateTray(true);
  console.log('[Astra] System proxy enabled');
}

async function disableProxy() {
  // Clear system proxy
  await session.defaultSession.setProxy({ proxyRules: '' });
  store.set('proxy_enabled', false);
  updateTray(false);
  console.log('[Astra] System proxy disabled');
}

// ── Tray ──────────────────────────────────────────────────────────────────────

function createTray() {
  // Use template image for Mac dark mode support
  const iconPath = path.join(__dirname, '../public/tray-icon.png');
  const icon     = nativeImage.createFromPath(iconPath);

  tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon);
  tray.setToolTip('Astra — AI Privacy Layer');

  updateTray(store.get('proxy_enabled', false));

  tray.on('click', () => {
    showStats();
  });
}

function updateTray(enabled) {
  if (!tray) return;

  const stats = getStats();

  const menu = Menu.buildFromTemplate([
    {
      label:   enabled ? '🛡 Astra Active' : '⚪ Astra Paused',
      enabled: false,
    },
    { type: 'separator' },
    {
      label:   `Protected today: ${stats.today}`,
      enabled: false,
    },
    {
      label:   `Total intercepted: ${stats.total}`,
      enabled: false,
    },
    { type: 'separator' },
    {
      label:   enabled ? 'Pause Protection' : 'Enable Protection',
      click:   () => enabled ? disableProxy() : enableProxy(),
    },
    {
      label: 'Settings',
      click: () => openSettings(),
    },
    {
      label: 'View Audit Log',
      click: () => openAuditLog(),
    },
    { type: 'separator' },
    {
      label: 'Quit Astra',
      click: () => { app.exit(0); },
    },
  ]);

  tray.setContextMenu(menu);
  tray.setTitle(enabled ? `${stats.today}` : '');
}

function showStats() {
  updateTray(store.get('proxy_enabled', false));
}

// ── Settings window ───────────────────────────────────────────────────────────

function openSettings() {
  if (settingsWindow) {
    settingsWindow.focus();
    return;
  }

  settingsWindow = new BrowserWindow({
    width:           500,
    height:          600,
    resizable:       false,
    titleBarStyle:   'hiddenInset',
    webPreferences:  {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
  });

  settingsWindow.loadFile(path.join(__dirname, '../public/settings.html'));

  settingsWindow.on('closed', () => {
    settingsWindow = null;
  });
}

function openAuditLog() {
  openSettings();
}

// ── IPC handlers ──────────────────────────────────────────────────────────────

function setupIPC() {
  ipcMain.handle('get-stats',    () => getStats());
  ipcMain.handle('get-settings', () => ({
    api_key:      store.get('api_key', ''),
    auto_start:   store.get('auto_start', true),
    proxy_enabled: store.get('proxy_enabled', false),
    proxy_port:   proxyPort,
  }));

  ipcMain.handle('save-settings', (event, settings) => {
    if (settings.api_key)    store.set('api_key',    settings.api_key);
    if (settings.auto_start !== undefined) store.set('auto_start', settings.auto_start);
    return { saved: true };
  });

  ipcMain.handle('toggle-proxy', async (event, enable) => {
    if (enable) await enableProxy();
    else        await disableProxy();
    return { enabled: enable };
  });

  ipcMain.handle('reset-stats', () => {
    resetStats();
    return { reset: true };
  });

  ipcMain.handle('cert-status', () => ({
    installed: store.get('cert_installed', false) || isCertInstalled(),
  }));

  ipcMain.handle('remove-cert', async () => {
    const ok = await removeCert();
    if (ok) store.set('cert_installed', false);
    return { removed: ok };
  });

  ipcMain.handle('get-audit-log', () => {
    const { getAuditLog } = require('./vault/vault');
    return getAuditLog(50);
  });
}

module.exports = { enableProxy, disableProxy };
