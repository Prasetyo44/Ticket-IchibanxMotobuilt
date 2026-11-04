# Ichiban x Motobuilt — Ticketing (Cloudflare Workers + D1)

Website tiket event IMOS untuk karyawan PT Warnatama Cemerlang. Berjalan penuh di Cloudflare (gratis, tanpa komputer yang menyala terus).

- Maksimal **2 tiket per karyawan** (karyawan + 1 tamu).
- Admin meng-upload file QR asli dari IMOS (PNG/JPG/WebP/PDF), **satu file = satu tiket**. File disimpan apa adanya, tidak diubah.
- Karyawan mengisi form dan **langsung** melihat tiketnya di website. Tidak ada WhatsApp/email.
- QR terkunci ke satu pendaftaran. Kalau dibatalkan (oleh karyawan atau panitia), QR hilang dari halaman tiketnya dan **kembali ke stok** untuk karyawan lain.
- ID karyawan yang pernah dibatalkan tidak bisa daftar lagi kecuali panitia mengizinkan (sekali pakai).
- Pemeriksaan di gerbang memakai sistem IMOS, bukan aplikasi ini.
- **Maksimal 2 tiket per karyawan, dikunci di server.** Kalau butuh lebih, karyawan mengajukan "tiket tambahan" dari halaman tiketnya (verifikasi ID + No HP, nama tamu tambahan, alasan). Admin/HRD melihatnya di tab **Tiket tambahan** (ada penanda jumlah yang menunggu), lalu menyetujui (QR diambil dari stok dan langsung muncul di halaman tiket karyawan) atau menolak.
- **Hanya untuk karyawan:** (1) daftar karyawan (NIK) membatasi siapa yang bisa daftar, (2) **kode akses** di Pengaturan menutup form sampai kode benar dimasukkan, (3) alamat dibuat sulit ditebak dan tidak terindeks mesin pencari (lihat DEPLOY.md).
- **Tidak terindeks Google:** semua halaman dan API mengirim `X-Robots-Tag: noindex, nofollow, noarchive`, ada `<meta robots>` di tiap halaman, dan `robots.txt` melarang semua crawler. Alamat bawaan `workers.dev` dimatikan.

## Halaman

| Alamat | Untuk | Fungsi |
|---|---|---|
| `/` | Karyawan | Form pendaftaran + "Buka tiket saya" |
| `/t/<token>` | Karyawan & tamu | E-ticket berisi QR dari IMOS, tombol "Batalkan tiket saya" |
| `/admin` (atau alamat rahasia dari `ADMIN_PATH`) | Admin | Ringkasan, peserta, karyawan, stok QR IMOS, pengaturan |

## Aturan yang dijalankan sistem

- 1 ID karyawan = 1 pendaftaran aktif = maksimal 2 tiket. 1 No HP = 1 pendaftar aktif. Dijaga langsung oleh database, jadi tidak bisa dilewati.
- Pengambilan QR dari stok dan pembuatan tiket terjadi dalam satu transaksi. Dua orang yang mendaftar bersamaan tidak mungkin mendapat file yang sama; kalau stok tinggal satu, yang kalah mendapat pesan "Kuota tiket sudah habis".
- Sisa tiket = jumlah file di stok (dan dibatasi kuota di Pengaturan bila diisi). Stok habis atau lewat batas waktu: form tertutup.
- Batal sendiri butuh ID karyawan + No HP yang sama dengan saat daftar dan centang konfirmasi. Orang yang hanya memegang link tidak bisa membatalkan.
- Link tiket berisi token acak panjang. Buka lagi lewat "Buka tiket saya" (ID karyawan + No HP, dibatasi percobaannya).
- File upload dicek dari isinya (PNG, JPG, WebP, PDF), maksimal **1 MB per file**; file dengan isi sama tidak masuk dua kali.
- Login admin dibatasi percobaannya; cookie `HttpOnly` + `SameSite=Strict`; export CSV aman dari formula injection Excel.

## Batas pengamanan

Website tidak bisa mencegah screenshot atau foto layar. Karena kode QR milik IMOS dan sama persis saat dipakai ulang, orang yang menyimpan QR sebelum dibatalkan masih bisa mencobanya di gerbang. Pastikan ke IMOS bahwa satu QR hanya bisa dipindai sekali.

## Pasang

Lihat **DEPLOY.md**. Ringkasnya: buat database D1, jalankan migrasi, `wrangler deploy`, isi `ADMIN_PASSWORD`, pasang custom domain.

## Uji lokal

```bash
npm install
cp .dev.vars.example .dev.vars        # isi ADMIN_PASSWORD
npm run db:local
npm run dev                           # http://localhost:8787
```

## Struktur

```
src/index.js              Worker: API, aturan pendaftaran, stok QR, sesi admin
migrations/0001_init.sql  Skema database D1
public/                   Halaman (form, tiket, admin) + poster
wrangler.jsonc            Konfigurasi Cloudflare
```
