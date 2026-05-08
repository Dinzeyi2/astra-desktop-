/**
 * Astra Desktop — Main Process v2
 * Fixed: cert installation, tray icon, settings window
 */
'use strict';

const { app, BrowserWindow, Tray, Menu, nativeImage, session, ipcMain, dialog } = require('electron');
const path  = require('path');
const Store = require('electron-store');
const { startProxy, stopProxy } = require('./proxy/proxy');
const { getStats, resetStats, getAuditLog } = require('./vault/vault');
const { generateCA, setupCertificate, isCertInstalled, removeCert } = require('./proxy/cert-installer');

const store      = new Store();
const PROXY_PORT = 8877;
let   tray       = null;
let   settingsWin = null;
let   CA          = null;

// ── App ready ─────────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  if (process.platform === 'darwin') app.dock.hide();

  // Generate CA cert
  CA = generateCA();

  // Start proxy first so app is usable immediately
  await startProxy(PROXY_PORT, CA.cert, CA.key).catch(err => {
    console.error('[Astra] Proxy start failed:', err.message);
  });

  // Set system proxy
  await enableSystemProxy();

  // Create tray
  createTray();

  // Setup IPC
  setupIPC();

  // Install cert if not done yet (non-blocking)
  const certDone = store.get('cert_installed', false) || isCertInstalled();
  if (!certDone) {
    installCertSilently();
  }

  // Open settings on first run so user can add API key
  if (!store.get('api_key', '')) {
    setTimeout(() => openSettings(), 1000);
  }
});

app.on('before-quit', async () => {
  await disableSystemProxy();
  await stopProxy();
});

app.on('window-all-closed', e => e.preventDefault());

// ── Proxy ─────────────────────────────────────────────────────────────────────

async function enableSystemProxy() {
  await session.defaultSession.setProxy({
    proxyRules: `http=127.0.0.1:${PROXY_PORT};https=127.0.0.1:${PROXY_PORT}`,
  });
  store.set('proxy_enabled', true);
  console.log('[Astra] System proxy enabled');
}

async function disableSystemProxy() {
  await session.defaultSession.setProxy({ proxyRules: '' });
  store.set('proxy_enabled', false);
}

// ── Cert installation ─────────────────────────────────────────────────────────

async function installCertSilently() {
  // Write cert to disk then run security command
  const { writeCertToTemp } = require('./proxy/cert-installer');
  const certPath = writeCertToTemp(CA.certPem);

  const { response } = await dialog.showMessageBox({
    type:      'info',
    title:     'Astra — One Time Setup',
    message:   'Install Security Certificate',
    detail:    'Astra needs to install a local certificate to protect HTTPS traffic to AI services.\n\nYou will be asked for your Mac password once. This is a one-time step.',
    buttons:   ['Install Now', 'Skip'],
    defaultId: 0,
    cancelId:  1,
  });

  if (response === 1) {
    console.log('[Astra] Certificate skipped');
    return;
  }

  const { exec } = require('child_process');
  const script   = `do shell script "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '${certPath}'" with administrator privileges`;

  exec(`osascript -e "${script.replace(/"/g, '\\"')}"`, (err) => {
    if (err) {
      console.error('[Astra] Cert install failed:', err.message);
      dialog.showMessageBox({
        type:    'warning',
        title:   'Certificate Not Installed',
        message: 'You can install it manually later from Settings.',
        buttons: ['OK'],
      });
    } else {
      store.set('cert_installed', true);
      console.log('[Astra] Certificate installed');
      dialog.showMessageBox({
        type:    'info',
        title:   '🛡 Astra Ready',
        message: 'Certificate installed. Astra is now protecting all AI traffic.',
        buttons: ['OK'],
      });
    }
  });
}

// ── Tray ──────────────────────────────────────────────────────────────────────

function createTray() {
  // Create a simple green square as fallback icon
  let icon;
  const iconPath = path.join(__dirname, '../public/icon.png');
  const fs = require('fs');

  if (fs.existsSync(iconPath)) {
    icon = nativeImage.createFromPath(iconPath);
  }

  // If icon missing or empty — create programmatic icon
  if (!icon || icon.isEmpty()) {
    // 16x16 green icon as base64 PNG
    const greenPNG = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAABSSURBVDiNY/z//z8DJYCJgUIwasCoAaMGjBowasCoAaMGjBowasCoAaMGjBowasCoAaMGjBowasCoAaMGjBowasCoAaMGjBowasCoAaMGDBgAAP//aVoGvhE5NKAAAAAASUVORK5CYII=',
      'base64'
    );
    icon = nativeImage.createFromBuffer(greenPNG);
    icon = icon.resize({ width: 16, height: 16 });
  }

  tray = new Tray(icon);
  tray.setToolTip('Astra — AI Privacy Layer');
  updateTrayMenu();
}

function updateTrayMenu() {
  if (!tray) return;
  const stats   = getStats();
  const enabled = store.get('proxy_enabled', true);
  const apiKey  = store.get('api_key', '');

  const menu = Menu.buildFromTemplate([
    { label: enabled ? '🛡  Astra Active' : '⚪  Astra Paused', enabled: false },
    { type: 'separator' },
    { label: `Protected today: ${stats.today}`,  enabled: false },
    { label: `Total protected: ${stats.total}`,  enabled: false },
    { label: apiKey ? '✅  API Key set' : '⚠️  No API Key — click Settings', enabled: false },
    { type: 'separator' },
    {
      label: enabled ? 'Pause Protection' : 'Enable Protection',
      click: async () => {
        if (enabled) { await disableSystemProxy(); }
        else         { await enableSystemProxy();  }
        updateTrayMenu();
      },
    },
    {
      label: '⚙️  Settings',
      click: () => openSettings(),
    },
    { type: 'separator' },
    { label: 'Quit Astra', click: () => app.quit() },
  ]);

  tray.setContextMenu(menu);
  tray.setTitle(enabled && stats.today > 0 ? `${stats.today}` : '');
}

// ── Settings window ───────────────────────────────────────────────────────────

function openSettings() {
  if (settingsWin) { settingsWin.focus(); return; }

  settingsWin = new BrowserWindow({
    width:          480,
    height:         580,
    resizable:      false,
    titleBarStyle:  'hiddenInset',
    title:          'Astra Settings',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
  });

  settingsWin.loadFile(path.join(__dirname, '../public/settings.html'));
  settingsWin.on('closed', () => { settingsWin = null; });
}

// ── IPC ───────────────────────────────────────────────────────────────────────

function setupIPC() {
  ipcMain.handle('get-stats',    () => getStats());
  ipcMain.handle('get-audit-log', () => getAuditLog(50));

  ipcMain.handle('get-settings', () => ({
    api_key:       store.get('api_key', ''),
    proxy_enabled: store.get('proxy_enabled', true),
    cert_installed: store.get('cert_installed', false) || isCertInstalled(),
  }));

  ipcMain.handle('save-settings', (e, s) => {
    if (s.api_key !== undefined) {
      store.set('api_key', s.api_key);
      // Update proxy with new key
      const { setApiKey } = require('./proxy/proxy');
      if (setApiKey) setApiKey(s.api_key);
    }
    updateTrayMenu();
    return { saved: true };
  });

  ipcMain.handle('toggle-proxy', async (e, enable) => {
    if (enable) await enableSystemProxy();
    else        await disableSystemProxy();
    updateTrayMenu();
    return { enabled: enable };
  });

  ipcMain.handle('install-cert', async () => {
    await installCertSilently();
    return { done: true };
  });

  ipcMain.handle('reset-stats', () => {
    resetStats();
    updateTrayMenu();
    return { reset: true };
  });
}
