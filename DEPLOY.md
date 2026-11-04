# Panduan pasang di Cloudflare (gratis, tanpa kartu)

Hasil akhir: aplikasi berjalan di Cloudflare Workers + D1 pada alamat acak di bawah ichiban.id (langkah 5). Tidak butuh komputer yang menyala.

## Yang dibutuhkan
- Akun Cloudflare yang sudah mengelola `ichiban.id`.
- Node.js 22 atau lebih baru di komputer kamu (hanya untuk memasang, bukan untuk menjalankan).
- Akun GitHub (opsional, untuk menyimpan kode).

## 1. Simpan kode di GitHub (opsional, disarankan)
Buat repository **private**, lalu:
```bash
cd imos-ticketing-cf
git init && git add . && git commit -m "Ticketing Ichiban x Motobuilt"
git branch -M main
git remote add origin https://github.com/<username>/ichiban-tiket.git
git push -u origin main
```
`.dev.vars` dan `node_modules/` sudah di `.gitignore`.

## 2. Siapkan alat
```bash
npm install
npx wrangler login        # browser terbuka, izinkan akses ke akun Cloudflare
```

## 3. Buat database D1
```bash
npx wrangler d1 create ichiban-tiket
```
Salin `database_id` yang tampil, lalu tempel di `wrangler.jsonc` (ganti `ISI-DENGAN-ID-DATABASE-D1`).

Buat tabelnya:
```bash
npm run db:remote
```
(Alternatif tanpa terminal: Cloudflare Dashboard → Storage & Databases → D1 → `ichiban-tiket` → Console, tempel isi `migrations/0001_init.sql`, lalu Execute.)

## 4. Pasang Worker
```bash
npx wrangler deploy
```
Alamat sementara `https://ichiban-tiket.<akun>.workers.dev` langsung aktif.

Isi password admin (pilih salah satu):
- Terminal: `npx wrangler secret put ADMIN_PASSWORD`
- Dashboard: Workers & Pages → `ichiban-tiket` → Settings → Variables and Secrets → Add → tipe **Secret**, nama `ADMIN_PASSWORD`.

## 5. Pasang alamat yang sulit ditebak
Pilih subdomain acak yang tidak ada hubungannya dengan kata "tiket", misalnya `k7q2x9m4pw.ichiban.id` (buat sendiri, 10 karakter huruf kecil dan angka acak).

Dashboard → Workers & Pages → `ichiban-tiket` → Settings → **Domains & Routes** → Add → **Custom domain** → isi subdomain itu.
Cloudflare membuat record DNS-nya otomatis. Website utama `ichiban.id` tidak tersentuh. Alamat `workers.dev` sudah dimatikan di `wrangler.jsonc`, jadi hanya alamat ini yang bisa dipakai.

Yang melindungi bukan alamat acak saja, tapi gabungan ini:
1. **Tidak terindeks:** semua halaman memakai `noindex`, dan `robots.txt` melarang crawler. Google tidak akan menampilkannya di hasil pencarian, selama alamatnya tidak tersebar di halaman publik.
2. **Alamat sulit ditebak** (subdomain acak). Ini hanya menyamarkan; siapa pun yang mendapat link-nya bisa membukanya, jadi jangan menaruhnya di website atau media sosial publik. Cloudflare umumnya memakai sertifikat wildcard (`*.ichiban.id`), jadi subdomain tidak muncul sendiri di daftar sertifikat publik, tapi itu tidak dijamin.
3. **Kode akses karyawan** (Admin → Pengaturan): tanpa kode, form pendaftaran tidak tampil dan tidak bisa dipakai. Bagikan kode lewat grup karyawan, dan ganti kalau bocor.
4. **Daftar karyawan** (Admin → Karyawan): hanya NIK yang ada di daftar yang bisa mendaftar.
5. Tiket hanya terbuka lewat link berisi token acak panjang.

## 6. Sebelum dibuka ke karyawan
1. Buka halaman admin (`/admin`, atau alamat rahasia yang kamu isi di variabel `ADMIN_PATH`), login dengan `ADMIN_PASSWORD`.
2. **Stok QR IMOS**: upload semua file dari IMOS (maksimal 1 MB per file).
3. **Pengaturan**: tanggal, tempat, kuota, batas waktu pendaftaran, dan **Kode akses karyawan**.
4. **Karyawan**: tempel `NIK, Nama, Bagian` supaya hanya karyawan resmi yang bisa daftar.
5. Daftar dengan data sendiri, lihat tiket di HP, batalkan, lalu cek QR kembali ke stok. Setelah itu hapus data uji (D1 → Console: `DELETE FROM tickets; DELETE FROM registrations; DELETE FROM rereg_allow; UPDATE qr_stock SET status='available', reg_id=NULL;`).
6. Bagikan link dan kode akses ke grup karyawan (jangan ke tempat publik).
7. Selama pendaftaran, cek tab **Tiket tambahan** secara berkala untuk permintaan tiket di atas 2. Pastikan stok QR cukup sebelum menyetujui.

## Update aplikasi
Ubah kode, lalu `npx wrangler deploy` lagi. Data di D1 tidak terhapus.

## Backup
Admin → Peserta → **Export CSV** (data peserta). File QR berasal dari IMOS, jadi simpan file aslinya juga.

## Batas paket gratis
Workers gratis: 100.000 permintaan per hari. D1 gratis: 5 juta baris dibaca dan 100.000 baris ditulis per hari. Untuk satu event perusahaan, batas ini sangat longgar. Angka bisa berubah; cek halaman harga Cloudflare.

## Kalau ada masalah
| Gejala | Cek |
|---|---|
| Login admin: "ADMIN_PASSWORD belum diatur" | Langkah 4, secret belum dibuat |
| Error 500 saat daftar | Migrasi belum dijalankan (langkah 3) atau `database_id` salah |
| Upload QR ditolak | File lebih dari 1 MB atau bukan PNG/JPG/WebP/PDF |
| Alamat tidak terbuka | Tunggu beberapa menit; cek Domains & Routes statusnya Active |
| Karyawan lupa kode akses | Lihat/ganti di Admin → Pengaturan |
