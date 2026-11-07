// Service Worker — OTP Authenticator Extension
// Minimal background service worker required by Manifest V3

chrome.runtime.onInstalled.addListener(() => {
  console.log('OTP Authenticator installed.');
});
