# People's Choice (Worker ketiga)

Situs voting motor: pengunjung mengisi data singkat lalu memberi 1 suara per kategori. Kode ada di repo yang sama.

1. Buat D1 baru bernama `ichiban-pilihan`, lalu isi tabel dengan `pilihan/schema-pilihan.sql` (Console D1).
2. Isi `database_id` di `wrangler.pilihan.jsonc`, lalu push.
3. Buat Worker `ichiban-pilihan` dari repo ini. Deploy command: `npx wrangler deploy -c wrangler.pilihan.jsonc`.
4. Secret: `ADMIN_PASSWORD` dan `ADMIN_PATH` (berbeda dari situs lain). Opsional: `TURNSTILE_SITE_KEY` dan `TURNSTILE_SECRET`.
5. Custom domain, mis. `pilihan.ichiban.ai.id`.
6. Di admin: buat kategori dan motor, isi kode lokasi, lalu ubah status ke Dibuka.

Pembatasan curang: satu nomor HP = satu pemilih, satu perangkat (cookie) = satu pemilih, batas pendaftaran per jaringan, kode lokasi opsional, Turnstile opsional, dan admin bisa membatalkan pemilih yang mencurigakan.
