# Mode umum (Worker kedua)

Kode yang sama dipakai dua situs yang terpisah penuh. Masing-masing punya Worker, database D1, stok QR, dan admin sendiri.

| | Karyawan | Umum |
|---|---|---|
| Worker | `ichiban-tiket` | `ichiban-tiket-umum` |
| Konfigurasi | `wrangler.jsonc` | `wrangler.umum.jsonc` (`MODE=umum`) |
| Database D1 | `ichiban-tiket` | `ichiban-tiket-umum` |
| Identitas | ID karyawan + No. HP | Email + No. HP |
| Tiket tambahan | Ajukan ke HRD | Tidak tersedia (maksimal 2 per orang) |

## Langkah
1. Buat D1 `ichiban-tiket-umum`, lalu jalankan isi `umum/schema-umum.sql` di tab Console (tanpa komentar, aman ditempel).
2. Isi `database_id` di `wrangler.umum.jsonc`.
3. Workers & Pages → Create → Import a repository (repo yang sama) → nama `ichiban-tiket-umum` → Deploy command: `npx wrangler deploy -c wrangler.umum.jsonc`.
4. Settings → Variables and Secrets (tipe **Secret**): `ADMIN_PASSWORD`, `ADMIN_PATH`.
5. Domains & Routes → Custom domain → mis. `umum.ichiban.ai.id`.
6. Anti-bot (disarankan): Turnstile → Add widget (hostname domain umum). Isi `TURNSTILE_SITE_KEY` (site key) dan `TURNSTILE_SECRET` (secret key) sebagai Secret.
7. Opsional agar halaman pendaftaran bisa ditemukan Google: variabel `SEO_INDEX` = `1`. Halaman tiket, file QR, API, dan admin tetap tersembunyi.

## Catatan
- Di mode umum, kolom `nik` di database menyimpan No. HP (kunci identitas); `dept` = `Umum`; `address` = `-`.
- Email dan No. HP masing-masing hanya boleh satu pendaftaran aktif.
- Jika `TURNSTILE_SECRET` tidak diisi, verifikasi anti-bot dilewati.
