# People's Choice (Worker ketiga)

Situs voting motor: pengunjung mengisi data singkat lalu memberi 1 suara per kategori. Kode ada di repo yang sama.

1. Buat D1 baru bernama `ichiban-pilihan`, lalu isi tabel dengan `pilihan/schema-pilihan.sql` (Console D1).
2. Isi `database_id` di `wrangler.pilihan.jsonc`, lalu push.
3. Buat Worker `ichiban-pilihan` dari repo ini. Deploy command: `npx wrangler deploy -c wrangler.pilihan.jsonc`.
4. Secret: `ADMIN_PASSWORD` dan `ADMIN_PATH` (berbeda dari situs lain). Opsional: `TURNSTILE_SITE_KEY` dan `TURNSTILE_SECRET`.
5. Custom domain, mis. `pilihan.ichiban.ai.id`.
6. Di admin: buat kategori dan motor, isi kode lokasi, lalu ubah status ke Dibuka.

Pembatasan curang: satu nomor HP = satu pemilih, satu perangkat (cookie) = satu pemilih, batas pendaftaran per jaringan, kode lokasi opsional, Turnstile opsional, dan admin bisa membatalkan pemilih yang mencurigakan.

## QR per motor dan impor data

1. Di halaman admin, buka tab Motor lalu pakai "Impor banyak motor sekaligus". Pilih file `import_motor.json` (kelas dibuat otomatis, nomor yang sudah ada diperbarui).
2. QR tiap motor mengarah ke `https://DOMAIN/m/NOMOR`. Buat lembar QR dengan:
   `python3 tools/qr_sheet.py import_motor.json https://DOMAIN QR_Motor.pdf 15`
3. Pastikan DOMAIN sudah final sebelum dicetak. QR yang sudah tercetak tidak bisa diubah arahnya.
4. Pengunjung juga bisa mengetik nomor motor di halaman utama kalau QR rusak.

## Specboard ber-QR

`python3 tools/specboard_qr.py Specboard.pdf https://pilihan.ichiban.ai.id Specboard_QR.pdf` menempel QR ke kotak "TEMPEL STICKER QR" di setiap halaman. Satu motor bisa ikut beberapa kelas: halaman motornya menampilkan tombol pilih untuk tiap kelas. Impor lewat admin menyinkronkan data (motor yang tidak ada di file dihapus).

## Undi pemenang (tab "🎁 Undi" di admin)

- **Juara motor per kelas**: dihitung dari suara sah (suara yang di-void tidak dihitung). Kalau ada seri di puncak, ditandai ⚠️ SERI supaya diputuskan sesuai aturan seri.
- **Undi pemenang pemilih**: acak kriptografis dari pemilih sah yang memberi minimal 1 suara. Pilihan peserta: semua pemilih, atau hanya pemilih juara sebuah kelas. Tersedia 0–5 pemenang cadangan.
- Pemenang utama undian sebelumnya tidak ikut diundi lagi; yang ditandai "Diterima"/"Gugur" juga dikeluarkan.
- Tandai "Diterima" saat hadiah diserahkan, atau "Gugur" bila tidak hadir, lalu hubungi cadangan berikutnya.
- Voting yang masih dibuka meminta konfirmasi sebelum undian. Disarankan: tutup voting, jalankan pemeriksaan pola mencurigakan, baru undi.
- Tabel `draws` dan `draw_winners` dibuat otomatis saat pertama dipakai, tidak perlu migrasi manual.
