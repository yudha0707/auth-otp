/**
 * OTP Authenticator — popup.js
 * TOTP (RFC 6238) implementation — Pure JavaScript, no external libraries.
 */

'use strict';

// ============================================================
//  TOTP Core Algorithm (RFC 6238 / HOTP RFC 4226)
// ============================================================

/**
 * Decode a Base32-encoded string to a Uint8Array.
 * Supports uppercase A-Z and 2-7, strips spaces and dashes.
 */
function base32Decode(input) {
  const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = input.toUpperCase().replace(/[\s-=]/g, '');

  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor((cleaned.length * 5) / 8));

  for (let i = 0; i < cleaned.length; i++) {
    const charIndex = BASE32_CHARS.indexOf(cleaned[i]);
    if (charIndex === -1) throw new Error(`Karakter tidak valid dalam secret key: '${cleaned[i]}'`);

    value = (value << 5) | charIndex;
    bits += 5;

    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return output;
}

/**
 * HMAC-SHA1 using SubtleCrypto API.
 * Returns ArrayBuffer.
 */
async function hmacSHA1(keyBytes, messageBytes) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', cryptoKey, messageBytes);
}

/**
 * Generate a TOTP code.
 * @param {string} secret   — Base32 secret key
 * @param {number} [time]   — Unix timestamp in seconds (default: now)
 * @param {number} [digits] — OTP digits (default: 6)
 * @param {number} [period] — TOTP period in seconds (default: 30)
 * @returns {Promise<string>} zero-padded OTP code
 */
async function generateTOTP(secret, time = Math.floor(Date.now() / 1000), digits = 6, period = 30) {
  const keyBytes = base32Decode(secret);

  // Counter = floor(time / period) as 8-byte big-endian
  const counter = Math.floor(time / period);
  const counterBytes = new Uint8Array(8);
  let tmp = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = tmp & 0xff;
    tmp = Math.floor(tmp / 256);
  }

  const hmac = await hmacSHA1(keyBytes.buffer, counterBytes.buffer);
  const hmacArray = new Uint8Array(hmac);

  // Dynamic truncation
  const offset = hmacArray[19] & 0xf;
  const code =
    ((hmacArray[offset]     & 0x7f) << 24) |
    ((hmacArray[offset + 1] & 0xff) << 16) |
    ((hmacArray[offset + 2] & 0xff) << 8)  |
     (hmacArray[offset + 3] & 0xff);

  const otp = code % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

// ============================================================
//  Storage Helpers
// ============================================================

/** Load all accounts from chrome.storage.local */
async function loadAccounts() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['accounts'], (result) => {
      resolve(result.accounts || []);
    });
  });
}

/** Save all accounts to chrome.storage.local */
async function saveAccounts(accounts) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ accounts }, resolve);
  });
}

// ============================================================
//  UI State
// ============================================================
let accounts = [];
let otpValues = {}; // { id: string }
let timerInterval = null;
let lastPeriod = Math.floor(Date.now() / 1000 / 30);

// ============================================================
//  DOM References
// ============================================================
const $container      = document.getElementById('accountsContainer');
const $emptyState     = document.getElementById('emptyState');
const $searchInput    = document.getElementById('searchInput');
const $timerBar       = document.getElementById('timerBar');
const $timerCountdown = document.getElementById('timerCountdown');
const $modalOverlay   = document.getElementById('modalOverlay');
const $btnOpenAdd     = document.getElementById('btnOpenAdd');
const $btnCloseModal  = document.getElementById('btnCloseModal');
const $btnCancelModal = document.getElementById('btnCancelModal');
const $btnSaveAccount = document.getElementById('btnSaveAccount');
const $btnExport      = document.getElementById('btnExport');
const $btnImport      = document.getElementById('btnImport');
const $importFileInput= document.getElementById('importFileInput');
const $inputName      = document.getElementById('inputName');
const $inputSecret    = document.getElementById('inputSecret');
const $formError      = document.getElementById('formError');
const $toast          = document.getElementById('toast');

// Scan Modal & Elements
const $scanModalOverlay  = document.getElementById('scanModalOverlay');
const $btnOpenScan       = document.getElementById('btnOpenScan');
const $btnCloseScanModal = document.getElementById('btnCloseScanModal');
const $btnEmptyScan      = document.getElementById('btnEmptyScan');
const $btnEmptyManual    = document.getElementById('btnEmptyManual');
const $scanTabs          = document.querySelectorAll('.scan-tab');
const $btnScanCurrentTab = document.getElementById('btnScanCurrentTab');
const $dropZone          = document.getElementById('dropZone');
const $qrFileInput       = document.getElementById('qrFileInput');
const $scanVideo         = document.getElementById('scanVideo');
const $screenScanStatus  = document.getElementById('screenScanStatus');
const $fileScanStatus    = document.getElementById('fileScanStatus');
const $cameraScanStatus  = document.getElementById('cameraScanStatus');

// ============================================================
//  Toast
// ============================================================
let toastTimeout = null;

function showToast(message, type = '') {
  $toast.textContent = message;
  $toast.className = 'toast show' + (type ? ` ${type}` : '');

  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    $toast.className = 'toast';
  }, 2200);
}

// ============================================================
//  Timer & OTP refresh
// ============================================================

function getSecondsUntilNextPeriod(period = 30) {
  const now = Math.floor(Date.now() / 1000);
  return period - (now % period);
}

async function refreshAllOTPs() {
  const time = Math.floor(Date.now() / 1000);
  for (const acc of accounts) {
    try {
      otpValues[acc.id] = await generateTOTP(acc.secret, time);
    } catch (e) {
      otpValues[acc.id] = 'ERROR';
    }
  }
}

function updateTimerUI() {
  const remaining = getSecondsUntilNextPeriod();
  const percent = (remaining / 30) * 100;

  $timerBar.style.width = percent + '%';
  $timerCountdown.textContent = remaining;

  // Update all OTP code elements
  const query = $searchInput.value.toLowerCase();
  const filtered = accounts.filter(a =>
    a.name.toLowerCase().includes(query)
  );

  filtered.forEach(acc => {
    const codeEl = document.getElementById(`otp-${acc.id}`);
    if (codeEl) {
      const val = otpValues[acc.id] || '------';
      // Format as "123 456"
      const formatted = val.substring(0, 3) + ' ' + val.substring(3);
      codeEl.textContent = formatted;

      // Urgent state
      if (remaining <= 7) {
        codeEl.classList.add('urgent');
      } else {
        codeEl.classList.remove('urgent');
      }
    }
  });
}

async function onPeriodTick() {
  await refreshAllOTPs();
  // Animate refresh on code elements
  const codeEls = document.querySelectorAll('.otp-code');
  codeEls.forEach(el => {
    el.classList.remove('refreshing');
    void el.offsetWidth; // reflow
    el.classList.add('refreshing');
  });
  updateTimerUI();
}

function startTimer() {
  if (timerInterval) clearInterval(timerInterval);

  lastPeriod = Math.floor(Date.now() / 1000 / 30);

  // Tick every second, check period change to prevent drift
  timerInterval = setInterval(async () => {
    const currentPeriod = Math.floor(Date.now() / 1000 / 30);

    if (currentPeriod !== lastPeriod) {
      lastPeriod = currentPeriod;
      await onPeriodTick();
    } else {
      updateTimerUI();
    }
  }, 1000);
}

// ============================================================
//  Render
// ============================================================

function getAvatarLetter(name) {
  return name.trim().charAt(0).toUpperCase() || '?';
}

function getAvatarClass(index) {
  return `avatar-${index % 8}`;
}

function renderAccounts() {
  const query = $searchInput.value.toLowerCase();
  const filtered = accounts.filter(a =>
    a.name.toLowerCase().includes(query)
  );

  if (accounts.length === 0) {
    $container.style.display = 'none';
    $emptyState.style.display = 'flex';
    return;
  }

  $emptyState.style.display = 'none';
  $container.style.display = 'flex';

  if (filtered.length === 0) {
    $container.innerHTML = `
      <div style="text-align:center; padding: 32px 16px; color: var(--text-muted); font-size:13px;">
        Tidak ada akun yang cocok dengan "<strong style="color:var(--text-secondary)">${escapeHtml(query)}</strong>"
      </div>`;
    return;
  }

  $container.innerHTML = filtered.map((acc, idx) => {
    const rawOtp = otpValues[acc.id] || '------';
    const formatted = rawOtp.substring(0, 3) + ' ' + rawOtp.substring(3);
    const avatarClass = getAvatarClass(accounts.indexOf(acc));
    const letter = getAvatarLetter(acc.name);

    return `
      <div class="account-card" data-id="${acc.id}">
        <div class="account-avatar ${avatarClass}">${escapeHtml(letter)}</div>
        <div class="account-info">
          <div class="account-name" title="${escapeHtml(acc.name)}">${escapeHtml(acc.name)}</div>
          <div class="otp-wrapper">
            <span class="otp-code" id="otp-${acc.id}">${formatted}</span>
            <span class="copy-hint" id="hint-${acc.id}">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
              Salin
            </span>
          </div>
        </div>
        <div class="card-actions">
          <button class="btn-delete" data-id="${acc.id}" title="Hapus akun">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
              <path d="M10 11v6M14 11v6"/>
              <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
            </svg>
          </button>
        </div>
      </div>
    `;
  }).join('');

  // Attach click handlers
  filtered.forEach(acc => {
    // Copy OTP on click
    const codeEl = document.getElementById(`otp-${acc.id}`);
    const hintEl = document.getElementById(`hint-${acc.id}`);
    if (codeEl) {
      codeEl.addEventListener('click', () => copyOTP(acc.id, hintEl));
    }
  });

  // Delete buttons
  document.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      deleteAccount(btn.dataset.id);
    });
  });
}

// ============================================================
//  Copy OTP
// ============================================================
async function copyOTP(id, hintEl) {
  const code = otpValues[id];
  if (!code || code === 'ERROR') return;

  try {
    await navigator.clipboard.writeText(code);
    if (hintEl) {
      hintEl.classList.add('copied');
      hintEl.innerHTML = `
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
        Tersalin!
      `;
      setTimeout(() => {
        hintEl.classList.remove('copied');
        hintEl.innerHTML = `
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
          Salin
        `;
      }, 2000);
    }
    showToast('✓ Kode OTP tersalin!', 'success');
  } catch {
    showToast('Gagal menyalin kode', 'error');
  }
}

// ============================================================
//  Delete Account
// ============================================================
async function deleteAccount(id) {
  const acc = accounts.find(a => a.id === id);
  if (!acc) return;

  if (!confirm(`Hapus akun "${acc.name}"?\n\nPastikan Anda sudah backup secret key sebelum menghapus!`)) return;

  accounts = accounts.filter(a => a.id !== id);
  delete otpValues[id];
  await saveAccounts(accounts);
  renderAccounts();
  showToast(`Akun "${acc.name}" dihapus`, 'error');
}

// ============================================================
//  Add Account Modal
// ============================================================
function openModal() {
  $inputName.value = '';
  $inputSecret.value = '';
  hideFormError();
  $modalOverlay.style.display = 'flex';
  setTimeout(() => $inputName.focus(), 50);
}

function closeModal() {
  $modalOverlay.style.display = 'none';
}

function showFormError(msg) {
  $formError.textContent = msg;
  $formError.style.display = 'block';
}

function hideFormError() {
  $formError.style.display = 'none';
}

// Convert byte array to Base32 string
function bytesToBase32(bytes) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += chars[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += chars[(value << (5 - bits)) & 31];
  }
  return output;
}

// Parse Google Authenticator export QR code (otpauth-migration://offline?data=...)
function parseOtpAuthMigrationUri(uri) {
  try {
    const url = new URL(uri.trim());
    if (!url.protocol.startsWith('otpauth-migration')) return null;
    const dataParam = url.searchParams.get('data');
    if (!dataParam) return null;

    const binStr = atob(dataParam);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }

    let pos = 0;
    const resultAccounts = [];

    function readVarint() {
      let res = 0;
      let shift = 0;
      while (pos < bytes.length) {
        const b = bytes[pos++];
        res |= (b & 0x7f) << shift;
        if ((b & 0x80) === 0) break;
        shift += 7;
      }
      return res;
    }

    while (pos < bytes.length) {
      const tag = readVarint();
      const fieldNum = tag >>> 3;
      const wireType = tag & 0x07;

      if (wireType === 2) {
        const len = readVarint();
        const end = pos + len;

        if (fieldNum === 1) { // otp_parameters
          let accSecret = null;
          let accName = '';
          let accIssuer = '';

          while (pos < end) {
            const innerTag = readVarint();
            const innerField = innerTag >>> 3;
            const innerWire = innerTag & 0x07;

            if (innerWire === 2) {
              const innerLen = readVarint();
              const subBytes = bytes.subarray(pos, pos + innerLen);
              pos += innerLen;

              if (innerField === 1) {
                accSecret = bytesToBase32(subBytes);
              } else if (innerField === 2) {
                accName = new TextDecoder().decode(subBytes);
              } else if (innerField === 3) {
                accIssuer = new TextDecoder().decode(subBytes);
              }
            } else if (innerWire === 0) {
              readVarint();
            } else {
              pos = end;
            }
          }

          if (accSecret) {
            let displayName = accName;
            if (accIssuer && !displayName.toLowerCase().includes(accIssuer.toLowerCase())) {
              displayName = `${accIssuer} (${displayName})`;
            }
            resultAccounts.push({
              name: displayName || accIssuer || 'Google Authenticator',
              secret: accSecret
            });
          }
        } else {
          pos = end;
        }
      } else if (wireType === 0) {
        readVarint();
      } else {
        break;
      }
    }
    return resultAccounts;
  } catch (err) {
    console.error('Error parsing migration payload:', err);
    return null;
  }
}

function parseOtpAuthUri(uri) {
  try {
    const trimmed = (uri || '').trim();
    if (!trimmed.toLowerCase().startsWith('otpauth://')) return null;
    const url = new URL(trimmed);
    const secret = url.searchParams.get('secret');
    if (!secret) return null;

    let pathPart = decodeURIComponent(url.pathname.replace(/^\/*totp\/*|\/*hotp\/*/i, ''));
    const issuerParam = url.searchParams.get('issuer');

    let displayName = pathPart;
    if (issuerParam && !displayName.toLowerCase().includes(issuerParam.toLowerCase())) {
      displayName = `${issuerParam} (${displayName})`;
    }
    return {
      name: displayName || issuerParam || 'Akun OTP',
      secret: secret.trim()
    };
  } catch {
    return null;
  }
}

// ============================================================
//  QR Code Decoder Engine
// ============================================================
async function decodeQRFromCanvas(canvas) {
  // Method 1: Native BarcodeDetector (super fast in Chrome)
  if ('BarcodeDetector' in window) {
    try {
      const detector = new BarcodeDetector({ formats: ['qr_code'] });
      const codes = await detector.detect(canvas);
      if (codes && codes.length > 0 && codes[0].rawValue) {
        return codes[0].rawValue;
      }
    } catch {}
  }

  // Method 2: jsQR Library (pure JS, offline)
  if (typeof jsQR !== 'undefined') {
    try {
      const ctx = canvas.getContext('2d');
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const res = jsQR(imgData.data, canvas.width, canvas.height, { inversionAttempts: 'dontInvert' }) ||
                  jsQR(imgData.data, canvas.width, canvas.height, { inversionAttempts: 'attemptBoth' });
      if (res && res.data) {
        return res.data;
      }
    } catch (e) {
      console.warn('jsQR error:', e);
    }
  }

  return null;
}

async function decodeQRFromImageSource(source) {
  const width = source.naturalWidth || source.videoWidth || source.width;
  const height = source.naturalHeight || source.videoHeight || source.height;
  if (!width || !height) return null;

  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(source, 0, 0, width, height);

  let result = await decodeQRFromCanvas(canvas);
  if (result) return result;

  // For high-res screens/screenshots (> 1200px), also try downscaling
  if (width > 1200) {
    const scale = 1000 / width;
    const scaledCanvas = document.createElement('canvas');
    scaledCanvas.width = 1000;
    scaledCanvas.height = Math.round(height * scale);
    const sCtx = scaledCanvas.getContext('2d');
    sCtx.drawImage(source, 0, 0, scaledCanvas.width, scaledCanvas.height);
    result = await decodeQRFromCanvas(scaledCanvas);
    if (result) return result;
  }

  return null;
}

async function decodeQRFromFile(file) {
  return new Promise((resolve) => {
    if (!file || !file.type.startsWith('image/')) {
      resolve(null);
      return;
    }
    const reader = new FileReader();
    reader.onload = async (e) => {
      const img = new Image();
      img.onload = async () => {
        const res = await decodeQRFromImageSource(img);
        resolve(res);
      };
      img.onerror = () => resolve(null);
      img.src = e.target.result;
    };
    reader.onerror = () => resolve(null);
    reader.readAsDataURL(file);
  });
}

// Process any decoded QR text into account(s)
async function processScannedCode(rawText) {
  if (!rawText || !rawText.trim()) return false;
  const text = rawText.trim();

  // Case 1: Google Authenticator migration payload
  if (text.toLowerCase().startsWith('otpauth-migration://')) {
    const migrated = parseOtpAuthMigrationUri(text);
    if (migrated && migrated.length > 0) {
      let added = 0;
      for (const item of migrated) {
        if (!accounts.some(a => a.secret === item.secret && a.name === item.name)) {
          accounts.push({
            id: generateId(),
            name: item.name,
            secret: item.secret,
            createdAt: Date.now()
          });
          added++;
        }
      }
      if (added > 0) {
        await saveAccounts(accounts);
        await refreshAllOTPs();
        renderAccounts();
        updateTimerUI();
        closeScanModal();
        showToast(`✓ Berhasil mengimpor ${added} akun dari Google Authenticator!`, 'success');
        return true;
      } else {
        showToast('Semua akun dari QR sudah ada di daftar.', 'error');
        return false;
      }
    } else {
      showToast('Gagal membaca data transfer Google Authenticator', 'error');
      return false;
    }
  }

  // Case 2: Standard otpauth://totp/... URL
  if (text.toLowerCase().startsWith('otpauth://')) {
    const parsed = parseOtpAuthUri(text);
    if (parsed) {
      const cleanSecret = parsed.secret.toUpperCase().replace(/[\s-=]/g, '');
      try {
        base32Decode(cleanSecret);
      } catch (err) {
        showToast(`Secret key tidak valid: ${err.message}`, 'error');
        return false;
      }

      if (accounts.some(a => a.secret === cleanSecret && a.name === parsed.name)) {
        showToast(`Akun "${parsed.name}" sudah ada.`, 'error');
        closeScanModal();
        return false;
      }

      const newAccount = {
        id: generateId(),
        name: parsed.name,
        secret: cleanSecret,
        createdAt: Date.now()
      };
      accounts.push(newAccount);
      otpValues[newAccount.id] = await generateTOTP(cleanSecret);
      await saveAccounts(accounts);
      closeScanModal();
      renderAccounts();
      updateTimerUI();
      showToast(`✓ Berhasil menambahkan "${parsed.name}"!`, 'success');
      return true;
    }
  }

  // Case 3: Plain Base32 Secret Key
  const clean = text.toUpperCase().replace(/[\s-=]/g, '');
  try {
    base32Decode(clean);
    if (clean.length >= 8) {
      closeScanModal();
      openModal();
      $inputSecret.value = clean;
      $inputName.value = 'Akun Baru';
      showToast('✓ Kunci rahasia terdeteksi! Beri nama akun.', 'success');
      return true;
    }
  } catch {}

  showToast('Kode QR bukan kode 2FA / Google Authenticator yang valid.', 'error');
  return false;
}

// ============================================================
//  Active Tab Scanner (Screen Capture)
// ============================================================
async function scanCurrentTab() {
  $screenScanStatus.textContent = 'Mengambil tangkapan layar tab...';
  $screenScanStatus.className = 'scan-status loading';

  try {
    const dataUrl = await new Promise((resolve, reject) => {
      chrome.tabs.captureVisibleTab(null, { format: 'png' }, (result) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else if (!result) {
          reject(new Error('Tidak dapat mengambil tangkapan layar tab.'));
        } else {
          resolve(result);
        }
      });
    });

    $screenScanStatus.textContent = 'Mendeteksi kode QR di halaman...';
    const img = new Image();
    img.onload = async () => {
      const qrData = await decodeQRFromImageSource(img);
      if (qrData) {
        $screenScanStatus.textContent = '✓ Kode QR ditemukan!';
        $screenScanStatus.className = 'scan-status success';
        await processScannedCode(qrData);
      } else {
        $screenScanStatus.textContent = 'QR code tidak terdeteksi di tab ini. Pastikan QR code terlihat di layar atau gunakan tab Upload/Kamera.';
        $screenScanStatus.className = 'scan-status error';
      }
    };
    img.onerror = () => {
      $screenScanStatus.textContent = 'Gagal memproses gambar layar tab.';
      $screenScanStatus.className = 'scan-status error';
    };
    img.src = dataUrl;
  } catch (err) {
    $screenScanStatus.textContent = `Gagal: ${err.message}. Halaman sistem Chrome tidak dapat dipindai.`;
    $screenScanStatus.className = 'scan-status error';
  }
}

// ============================================================
//  Camera Scanner (Webcam)
// ============================================================
let cameraStream = null;
let cameraAnimFrame = null;

async function startCamera() {
  stopCamera();
  $cameraScanStatus.textContent = 'Menghubungkan ke kamera...';
  $cameraScanStatus.className = 'scan-status loading';

  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } }
    });
    $scanVideo.srcObject = cameraStream;
    await $scanVideo.play();
    $cameraScanStatus.textContent = 'Arahkan kamera ke kode QR...';
    $cameraScanStatus.className = 'scan-status';

    scanCameraLoop();
  } catch (err) {
    $cameraScanStatus.textContent = `Kamera tidak dapat diakses: ${err.message}`;
    $cameraScanStatus.className = 'scan-status error';
  }
}

function stopCamera() {
  if (cameraAnimFrame) {
    cancelAnimationFrame(cameraAnimFrame);
    cameraAnimFrame = null;
  }
  if (cameraStream) {
    cameraStream.getTracks().forEach((track) => track.stop());
    cameraStream = null;
  }
  if ($scanVideo) {
    $scanVideo.srcObject = null;
  }
}

async function scanCameraLoop() {
  if (!cameraStream || $scanVideo.readyState !== $scanVideo.HAVE_ENOUGH_DATA) {
    cameraAnimFrame = requestAnimationFrame(scanCameraLoop);
    return;
  }

  const qrData = await decodeQRFromImageSource($scanVideo);
  if (qrData) {
    $cameraScanStatus.textContent = '✓ Kode QR terdeteksi!';
    $cameraScanStatus.className = 'scan-status success';
    stopCamera();
    await processScannedCode(qrData);
  } else {
    cameraAnimFrame = requestAnimationFrame(scanCameraLoop);
  }
}

// ============================================================
//  Scan Modal Management
// ============================================================
function openScanModal(defaultTab = 'tab-screen') {
  $screenScanStatus.textContent = '';
  $fileScanStatus.textContent = '';
  $cameraScanStatus.textContent = '';
  $scanModalOverlay.style.display = 'flex';
  switchScanTab(defaultTab);
}

function closeScanModal() {
  stopCamera();
  $scanModalOverlay.style.display = 'none';
}

function switchScanTab(tabId) {
  $scanTabs.forEach(t => {
    t.classList.toggle('active', t.dataset.tab === tabId);
  });

  const panels = {
    'tab-screen': document.getElementById('panel-screen'),
    'tab-file': document.getElementById('panel-file'),
    'tab-camera': document.getElementById('panel-camera'),
  };

  Object.keys(panels).forEach(key => {
    if (panels[key]) {
      panels[key].style.display = key === tabId ? 'flex' : 'none';
    }
  });

  if (tabId === 'tab-camera') {
    startCamera();
  } else {
    stopCamera();
  }
}

async function handleImageFile(file) {
  $fileScanStatus.textContent = 'Membaca gambar...';
  $fileScanStatus.className = 'scan-status loading';
  const qrData = await decodeQRFromFile(file);
  if (qrData) {
    $fileScanStatus.textContent = '✓ Kode QR ditemukan!';
    $fileScanStatus.className = 'scan-status success';
    await processScannedCode(qrData);
  } else {
    $fileScanStatus.textContent = 'Tidak ada kode QR yang terdeteksi di gambar ini.';
    $fileScanStatus.className = 'scan-status error';
  }
}

// ============================================================
//  Manual Add Account
// ============================================================
async function saveNewAccount() {
  hideFormError();
  let name = $inputName.value.trim();
  let rawSecret = $inputSecret.value.trim();

  // If user pasted an otpauth:// URI in either field
  const parsedUri = parseOtpAuthUri(rawSecret) || parseOtpAuthUri(name);
  if (parsedUri) {
    if (!name || name.toLowerCase().startsWith('otpauth://')) {
      name = parsedUri.name;
    }
    rawSecret = parsedUri.secret;
  }

  const secret = rawSecret.toUpperCase().replace(/[\s-=]/g, '');

  if (!name) {
    showFormError('Nama akun tidak boleh kosong.');
    $inputName.focus();
    return;
  }

  if (!secret) {
    showFormError('Secret key tidak boleh kosong.');
    $inputSecret.focus();
    return;
  }

  // Validate secret key by attempting decode + generate
  try {
    base32Decode(secret);
    await generateTOTP(secret);
  } catch (e) {
    showFormError(`Secret key tidak valid: ${e.message}`);
    $inputSecret.focus();
    return;
  }

  // Check duplicate
  if (accounts.some(a => a.secret === secret && a.name === name)) {
    showFormError('Akun dengan nama dan secret key yang sama sudah ada.');
    return;
  }

  const newAccount = {
    id: generateId(),
    name,
    secret,
    createdAt: Date.now(),
  };

  accounts.push(newAccount);
  otpValues[newAccount.id] = await generateTOTP(secret);
  await saveAccounts(accounts);
  closeModal();
  renderAccounts();
  updateTimerUI();
  showToast(`✓ Akun "${name}" berhasil ditambahkan!`, 'success');
}

// ============================================================
//  Export & Import Backup
// ============================================================
function exportAccounts() {
  if (accounts.length === 0) {
    showToast('Belum ada akun untuk dicadangkan.', 'error');
    return;
  }

  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(accounts, null, 2));
  const downloadAnchor = document.createElement('a');
  const dateStr = new Date().toISOString().slice(0, 10);
  downloadAnchor.setAttribute('href', dataStr);
  downloadAnchor.setAttribute('download', `otp-authenticator-backup-${dateStr}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();

  showToast('✓ Cadangan berhasil diunduh!', 'success');
}

function importAccounts(file) {
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const imported = JSON.parse(e.target.result);
      if (!Array.isArray(imported)) {
        throw new Error('Format file tidak valid (harus array akun).');
      }

      let addedCount = 0;
      for (const item of imported) {
        if (!item.name || !item.secret) continue;
        const cleanSecret = item.secret.toUpperCase().replace(/[\s-=]/g, '');

        try {
          base32Decode(cleanSecret);
        } catch {
          continue;
        }

        // Avoid exact duplicates
        if (!accounts.some(a => a.secret === cleanSecret && a.name === item.name)) {
          accounts.push({
            id: item.id || generateId(),
            name: item.name,
            secret: cleanSecret,
            createdAt: item.createdAt || Date.now()
          });
          addedCount++;
        }
      }

      if (addedCount > 0) {
        await saveAccounts(accounts);
        await refreshAllOTPs();
        renderAccounts();
        updateTimerUI();
        showToast(`✓ Berhasil memulihkan ${addedCount} akun!`, 'success');
      } else {
        showToast('Tidak ada akun baru yang ditambahkan.', 'error');
      }
    } catch (err) {
      showToast(`Gagal mengimpor file: ${err.message}`, 'error');
    } finally {
      $importFileInput.value = '';
    }
  };
  reader.readAsText(file);
}

// ============================================================
//  Helpers
// ============================================================
function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Auto-fill when pasting otpauth URI into secret input
function checkOtpAuthInput(el) {
  const val = el.value.trim();
  const parsed = parseOtpAuthUri(val);
  if (parsed) {
    $inputSecret.value = parsed.secret;
    if (!$inputName.value.trim() || $inputName.value.trim().toLowerCase().startsWith('otpauth://')) {
      $inputName.value = parsed.name;
    }
    showToast('✓ Link otpauth:// berhasil diurai!', 'success');
  }
}

// ============================================================
//  Event Listeners
// ============================================================
// Add Modal
$btnOpenAdd.addEventListener('click', openModal);
$btnCloseModal.addEventListener('click', closeModal);
$btnCancelModal.addEventListener('click', closeModal);
$btnSaveAccount.addEventListener('click', saveNewAccount);

// Scan Modal
$btnOpenScan.addEventListener('click', () => openScanModal('tab-screen'));
$btnCloseScanModal.addEventListener('click', closeScanModal);
$scanModalOverlay.addEventListener('click', (e) => {
  if (e.target === $scanModalOverlay) closeScanModal();
});

// Empty State Buttons
if ($btnEmptyScan) $btnEmptyScan.addEventListener('click', () => openScanModal('tab-screen'));
if ($btnEmptyManual) $btnEmptyManual.addEventListener('click', openModal);

// Scan Tabs
$scanTabs.forEach(tab => {
  tab.addEventListener('click', () => switchScanTab(tab.dataset.tab));
});

// Scan Active Tab Button
if ($btnScanCurrentTab) $btnScanCurrentTab.addEventListener('click', scanCurrentTab);

// Drop Zone & File Input
if ($dropZone && $qrFileInput) {
  $dropZone.addEventListener('click', () => $qrFileInput.click());
  $qrFileInput.addEventListener('change', async (e) => {
    if (e.target.files && e.target.files[0]) {
      await handleImageFile(e.target.files[0]);
      $qrFileInput.value = '';
    }
  });

  $dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    $dropZone.classList.add('dragover');
  });

  $dropZone.addEventListener('dragleave', () => {
    $dropZone.classList.remove('dragover');
  });

  $dropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    $dropZone.classList.remove('dragover');
    if (e.dataTransfer?.files && e.dataTransfer.files[0]) {
      await handleImageFile(e.dataTransfer.files[0]);
    }
  });
}

// Global Paste (Ctrl+V) listener for QR screenshots or otpauth links
document.addEventListener('paste', async (e) => {
  const activeTag = document.activeElement?.tagName;
  const isInputFocused = activeTag === 'INPUT' || activeTag === 'TEXTAREA';

  // 1. Check for image in clipboard
  const items = (e.clipboardData || e.originalEvent?.clipboardData)?.items;
  if (items) {
    for (const item of items) {
      if (item.type.indexOf('image') !== -1) {
        e.preventDefault();
        const file = item.getAsFile();
        if (file) {
          showToast('Membaca gambar dari clipboard...', '');
          const qrData = await decodeQRFromFile(file);
          if (qrData) {
            await processScannedCode(qrData);
          } else {
            showToast('Tidak ada kode QR yang terdeteksi di gambar.', 'error');
          }
          return;
        }
      }
    }
  }

  // 2. Check for otpauth or migration link text when not typing
  const text = (e.clipboardData || window.clipboardData)?.getData('text');
  if (text && (text.startsWith('otpauth://') || text.startsWith('otpauth-migration://'))) {
    if (!isInputFocused) {
      e.preventDefault();
      await processScannedCode(text);
    }
  }
});

// Export & Import Backup
$btnExport.addEventListener('click', exportAccounts);
$btnImport.addEventListener('click', () => $importFileInput.click());
$importFileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files[0]) {
    importAccounts(e.target.files[0]);
  }
});

// Auto detect otpauth link in secret or name input
$inputSecret.addEventListener('paste', () => setTimeout(() => checkOtpAuthInput($inputSecret), 50));
$inputSecret.addEventListener('input', () => checkOtpAuthInput($inputSecret));
$inputName.addEventListener('paste', () => setTimeout(() => checkOtpAuthInput($inputName), 50));

// Close modal on overlay click
$modalOverlay.addEventListener('click', (e) => {
  if (e.target === $modalOverlay) closeModal();
});

// Search
$searchInput.addEventListener('input', () => {
  renderAccounts();
  updateTimerUI();
});

// Save on Enter key
$inputSecret.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') saveNewAccount();
});
$inputName.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $inputSecret.focus();
});

// ============================================================
//  Initialization
// ============================================================
async function init() {
  accounts = await loadAccounts();
  await refreshAllOTPs();
  renderAccounts();
  updateTimerUI();
  startTimer();
}

init();
