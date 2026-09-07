# FALLSTOREE — Vercel-ready build

## Isi ZIP
- index.html — frontend utama, sudah disiapkan sebagai single-page storefront.
- api/index.js — Vercel Serverless Function.
- vercel.json — konfigurasi deployment.
- db.sql — schema Supabase.

## Yang perlu diatur di Vercel
Environment Variables:
- SUPABASE_URL = URL project Supabase
- SUPABASE_SERVICE_ROLE_KEY = Service Role Key Supabase

## Yang tetap ada di frontend
- Animasi / glitch / responsive UI
- User login/register
- Katalog produk
- Kategori TikTok, Instagram, Saluran WhatsApp, Lainnya
- Produk tanpa foto
- QRIS per produk
- Nomor WA penjual per produk
- Order → QRIS → WhatsApp
- Order Saya
- DONE / verifikasi order
- Nomor WA cadangan
- Developer/Admin management
- Blacklist / unblacklist
- Delete user protection
- Passkey/WebAuthn pada UI yang sudah ada di source
- Polling state sekitar 8 detik dan BroadcastChannel untuk sinkronisasi tab

## Deploy dari HP
1. Buat repository GitHub baru.
2. Upload isi folder ZIP ke root repository.
3. Import repository tersebut ke Vercel.
4. Di Vercel → Settings → Environment Variables, isi dua variable Supabase di atas.
5. Jalankan isi `db.sql` pada Supabase SQL Editor.
6. Redeploy di Vercel.
7. Buka domain Vercel.

## Catatan keamanan
Jangan menaruh Service Role Key di index.html.
Credential Developer utama sebaiknya tidak di-hardcode pada frontend. Build ini mempertahankan frontend existing, tetapi backend harus menjadi sumber otoritas untuk role/permission.

## Catatan penting
API di `api/index.js` memetakan action yang sudah dipakai oleh frontend existing. Jika schema/field berubah, sesuaikan API dan SQL bersama-sama.
