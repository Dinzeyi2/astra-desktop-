/**
 * Astra Certificate Installer
 * ============================
 * Installs the Astra local CA certificate as trusted on the system.
 * One-time setup. One sudo prompt. Everything works forever after.
 *
 * Mac:     security add-trusted-cert (requires sudo)
 * Windows: certutil -addstore (requires admin)
 * Linux:   update-ca-certificates (requires sudo)
 */

'use strict';

const { execSync, exec } = require('child_process');
const { dialog }         = require('electron');
const forge              = require('node-forge');
const fs                 = require('fs');
const path               = require('path');
const os                 = require('os');

// ── Generate and persist CA cert ─────────────────────────────────────────────

function generateCA() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey    = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: 'commonName',       value: 'Astra Local CA' },
    { name: 'organizationName', value: 'Codeastra' },
    { name: 'countryName',      value: 'US' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem:  forge.pki.privateKeyToPem(keys.privateKey),
    cert,
    key:     keys.privateKey,
  };
}

// ── Write cert to temp file ───────────────────────────────────────────────────

function writeCertToTemp(certPem) {
  const tempPath = path.join(os.tmpdir(), 'astra-ca.crt');
  fs.writeFileSync(tempPath, certPem);
  return tempPath;
}

// ── Install cert per platform ─────────────────────────────────────────────────

async function installCertMac(certPath) {
  return new Promise((resolve, reject) => {
    // Use osascript to prompt for admin password via native dialog
    const script = `
      do shell script "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '${certPath}'"
      with administrator privileges
    `;
    exec(`osascript -e '${script.replace(/'/g, "\\'")}'`, (err) => {
      if (err) reject(new Error('Certificate installation cancelled or failed'));
      else     resolve(true);
    });
  });
}

async function installCertWindows(certPath) {
  return new Promise((resolve, reject) => {
    // PowerShell with elevation prompt
    const cmd = `powershell -Command "Start-Process certutil -ArgumentList '-addstore','Root','${certPath}' -Verb RunAs -Wait"`;
    exec(cmd, (err) => {
      if (err) reject(new Error('Certificate installation cancelled or failed'));
      else     resolve(true);
    });
  });
}

async function installCertLinux(certPath) {
  return new Promise((resolve, reject) => {
    // Copy to trusted certs and update
    const destPath = `/usr/local/share/ca-certificates/astra-local-ca.crt`;
    exec(
      `pkexec sh -c "cp '${certPath}' '${destPath}' && update-ca-certificates"`,
      (err) => {
        if (err) reject(new Error('Certificate installation failed'));
        else     resolve(true);
      }
    );
  });
}

// ── Check if cert already installed ──────────────────────────────────────────

function isCertInstalled() {
  try {
    const platform = process.platform;
    if (platform === 'darwin') {
      const result = execSync('security find-certificate -c "Astra Local CA" /Library/Keychains/System.keychain 2>/dev/null').toString();
      return result.includes('Astra Local CA');
    }
    if (platform === 'win32') {
      const result = execSync('certutil -store Root "Astra Local CA" 2>nul').toString();
      return result.includes('Astra Local CA');
    }
    if (platform === 'linux') {
      return fs.existsSync('/usr/local/share/ca-certificates/astra-local-ca.crt');
    }
  } catch (_) {}
  return false;
}

// ── Remove cert (uninstall) ───────────────────────────────────────────────────

async function removeCert() {
  const platform = process.platform;
  try {
    if (platform === 'darwin') {
      execSync('osascript -e \'do shell script "security delete-certificate -c \\"Astra Local CA\\" /Library/Keychains/System.keychain" with administrator privileges\'');
    }
    if (platform === 'win32') {
      execSync('powershell -Command "Start-Process certutil -ArgumentList \'-delstore\',\'Root\',\'Astra Local CA\' -Verb RunAs -Wait"');
    }
    if (platform === 'linux') {
      execSync('pkexec rm /usr/local/share/ca-certificates/astra-local-ca.crt && update-ca-certificates');
    }
    return true;
  } catch (_) {
    return false;
  }
}

// ── Main setup flow ───────────────────────────────────────────────────────────

async function setupCertificate(certPem) {
  // Check if already installed
  if (isCertInstalled()) {
    console.log('[Astra] Certificate already installed');
    return { installed: true, already: true };
  }

  const platform = process.platform;

  // Show explanation dialog before prompting for admin
  const { response } = await dialog.showMessageBox({
    type:      'info',
    title:     'Astra Setup — One Time',
    message:   'Astra needs to install a local security certificate',
    detail:    'This certificate allows Astra to protect your AI traffic.\n\nIt only works on your device and expires in 10 years.\nYou can remove it anytime from Astra Settings.\n\nYou will be asked for your password once.',
    buttons:   ['Install Certificate', 'Cancel'],
    defaultId: 0,
    cancelId:  1,
    icon:      path.join(__dirname, '../../public/icon.png'),
  });

  if (response === 1) {
    return { installed: false, cancelled: true };
  }

  // Write cert to temp file
  const certPath = writeCertToTemp(certPem);

  try {
    if (platform === 'darwin') {
      await installCertMac(certPath);
    } else if (platform === 'win32') {
      await installCertWindows(certPath);
    } else {
      await installCertLinux(certPath);
    }

    // Clean up temp file
    fs.unlinkSync(certPath);

    // Show success
    await dialog.showMessageBox({
      type:    'info',
      title:   'Astra Ready',
      message: '🛡 Astra is now protecting your AI traffic',
      detail:  'All requests to ChatGPT, Claude, Gemini, and other AI services will be automatically protected.\n\nYou will never need to do this again.',
      buttons: ['Get Started'],
    });

    return { installed: true };

  } catch (err) {
    fs.unlinkSync(certPath);

    await dialog.showMessageBox({
      type:    'error',
      title:   'Setup Failed',
      message: 'Certificate installation failed',
      detail:  err.message + '\n\nAstra will still protect traffic in your browser via the Chrome extension.',
      buttons: ['OK'],
    });

    return { installed: false, error: err.message };
  }
}

// ── Generate server cert for a hostname ──────────────────────────────────────

const certCache = new Map();

function generateServerCert(hostname, caCert, caKey) {
  if (certCache.has(hostname)) return certCache.get(hostname);

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey    = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] },
    { name: 'extKeyUsage', serverAuth: true },
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  const result = {
    cert: forge.pki.certificateToPem(cert),
    key:  forge.pki.privateKeyToPem(keys.privateKey),
  };

  certCache.set(hostname, result);
  return result;
}

module.exports = {
  generateCA,
  setupCertificate,
  isCertInstalled,
  removeCert,
  generateServerCert,
  writeCertToTemp,
};
