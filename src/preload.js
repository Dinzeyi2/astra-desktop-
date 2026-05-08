/**
 * Astra Desktop Preload
 * Exposes IPC bridge to settings UI safely.
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('astra', {
  getStats:     () => ipcRenderer.invoke('get-stats'),
  getSettings:  () => ipcRenderer.invoke('get-settings'),
  saveSettings: (s) => ipcRenderer.invoke('save-settings', s),
  toggleProxy:  (e) => ipcRenderer.invoke('toggle-proxy', e),
  resetStats:   () => ipcRenderer.invoke('reset-stats'),
  getAuditLog:  () => ipcRenderer.invoke('get-audit-log'),
  certStatus:   () => ipcRenderer.invoke('cert-status'),
  removeCert:   () => ipcRenderer.invoke('remove-cert'),
});
