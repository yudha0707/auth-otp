# OTP Authenticator — Chrome Extension

Extension Chrome untuk melihat dan menghasilkan kode OTP (TOTP 6 digit) langsung dari browser Chrome di komputer/laptop Anda — alternatif terbaik saat handphone tertinggal atau tidak ada sinyal.

---

## ✨ Fitur Utama

- **📷 Pindai Kode QR Fleksibel (Tidak Perlu Ketik Manual!)**:
  1. **Pindai Tab Aktif (1-Klik)**: Otomatis mendeteksi QR code 2FA yang sedang tampil di layar web browser Anda.
  2. **Paste Screenshot (Ctrl + V)**: Cukup tekan `Win + Shift + S` untuk crop QR code di layar, lalu buka ekstensi dan tekan `Ctrl + V`!
  3. **Unggah Gambar**: Drag-and-drop atau pilih file gambar QR code.
  4. **Kamera / Webcam**: Arahkan QR code dari HP atau kertas ke kamera laptop/PC.
  5. **Dukungan Transfer Google Authenticator**: Bisa langsung memindai QR code "Ekspor Akun" dari aplikasi Google Authenticator HP (`otpauth-migration://`) untuk memindahkan semua akun sekaligus!
- **Real-Time 30-Second TOTP**: Mengikuti standar industri RFC 6238 (persis seperti Google Authenticator).
- **Salin Kode Sekali Klik**: Cukup klik angka OTP, kode otomatis tersalin ke clipboard.
- **Pencarian Cepat**: Filter akun dengan instan saat punya banyak akun.
- **Peringatan Waktu (Urgent State)**: Angka berubah merah berkedip saat sisa waktu di bawah 7 detik.
- **Cadangan & Pemulihan (JSON)**: Ekspor dan pulihkan semua akun Anda kapan saja ke file JSON.
- **100% Offline & Aman**: Menggunakan library lokal (`jsQR`), semua data tersimpan aman di penyimpanan lokal Chrome (`chrome.storage.local`), tanpa internet / server pihak ketiga.

---

## 🚀 Cara Memasang di Google Chrome

1. Buka browser **Google Chrome**.
2. Masuk ke halaman ekstensi: ketik `chrome://extensions/` di address bar dan tekan **Enter**.
3. Di pojok kanan atas, aktifkan tombol switch **Mode pengembang** (*Developer mode*).
4. Klik tombol **Muat yang belum dibongkar** (*Load unpacked*) di pojok kiri atas.
   *(Jika ekstensi sudah pernah dimuat sebelumnya, cukup klik ikon **Reload / Muat ulang 🔄** pada kartu OTP Authenticator)*.
5. Pilih folder:
   ```
   D:\nitp yudha\auth-otp
   ```
6. Ekstensi **OTP Authenticator** akan terpasang!
7. Klik ikon puzzle (Extensions) di toolbar Chrome sebelah kanan atas, lalu klik ikon **Pin** 📌 agar selalu tampil di toolbar.

---

## 📷 Cara Pindai Kode QR (Super Praktis!)

Ada 4 cara mudah memindai QR code tanpa perlu ribet mengetik kunci manual:

### Cara 1: Pindai Tab Aktif (1-Klik) — *Paling Mudah!*
1. Di tab Chrome Anda, buka halaman website yang menampilkan QR code 2FA (misal halaman setup Google, GitHub, dsb).
2. Klik ikon ekstensi **OTP Authenticator** di toolbar.
3. Klik tombol **Scan QR** di header (atau tombol *"Pindai Kode QR"* di tengah).
4. Klik tombol **"Pindai Tab Aktif Sekarang"**.
5. Ekstensi akan otomatis membaca QR code di layar Anda dan akun langsung tersimpan!

### Cara 2: Paste Screenshot (Ctrl + V)
1. Tekan tombol **Windows + Shift + S** di keyboard untuk memotong (crop) area QR code di layar Anda.
2. Buka ekstensi **OTP Authenticator**.
3. Tekan **Ctrl + V**. Selesai! Ekstensi langsung membaca QR code dari clipboard.

### Cara 3: Unggah File Gambar
1. Buka ekstensi, klik tombol **Scan QR**, pilih tab **Upload / Paste**.
2. Klik kotak dropzone untuk memilih file gambar QR code Anda (atau drag & drop filenya).

### Cara 4: Kamera Laptop / Webcam
1. Buka ekstensi, klik tombol **Scan QR**, pilih tab **Kamera**.
2. Berikan izin akses kamera jika diminta, lalu arahkan QR code (dari HP atau kertas) ke kamera.

---

## 📲 Cara Pindahkan Semua Akun Sekaligus dari Google Authenticator HP

Jika Anda punya banyak akun di aplikasi Google Authenticator di HP dan ingin disalin ke PC:
1. Buka aplikasi **Google Authenticator** di HP.
2. Buka menu samping / foto profil -> pilih **Transfer akun** (*Transfer accounts*) -> **Ekspor akun** (*Export accounts*).
3. Pilih akun yang ingin diekspor, lalu klik **Berikutnya** hingga muncul kode QR besar di layar HP Anda.
4. Buka ekstensi di laptop, klik **Scan QR** -> tab **Kamera**, lalu arahkan layar HP Anda ke webcam laptop.
   *(Atau foto QR tersebut, kirim ke PC, lalu gunakan tab **Upload / Paste**)*.
5. Ekstensi akan langsung mengimpor seluruh akun Anda sekaligus!

---

## 💾 Cadangan & Pemulihan (Backup & Restore)

- **Ekspor Cadangan**: Klik ikon unduh di header untuk menyimpan semua akun ke file `.json`.
- **Impor Cadangan**: Klik ikon unggah di header lalu pilih file `.json` cadangan untuk memulihkan akun kapan saja.
