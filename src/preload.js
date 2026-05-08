'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('astra', {
  getStats:    () => ipcRenderer.invoke('get-stats'),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: s => ipcRenderer.invoke('save-settings', s),
  toggleProxy:  e => ipcRenderer.invoke('toggle-proxy', e),
  installCert:  () => ipcRenderer.invoke('install-cert'),
  resetStats:   () => ipcRenderer.invoke('reset-stats'),
  getAuditLog:  () => ipcRenderer.invoke('get-audit-log'),
});
