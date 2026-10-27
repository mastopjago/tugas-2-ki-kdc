Kelompok
1. Kayana Danendra Kawiswara 5025231286
2. Ahmad Faiz Tajuddin 5025231291

# Tugas 2 KI — Key Distribution Scenario (KDC + AES Manual)

Implementasi skenario distribusi kunci dengan **KDC, Alice, dan Bob** di 3 perangkat (3 IP berbeda).
Setelah langkah ke-5, Alice dan Bob saling mengirim pesan terenkripsi **AES** secara dua arah.
AES, KDC, dan PRNG dibuat **manual** tanpa library kriptografi. Program hanya memakai Python standard library.

## Struktur file

| File | Isi |
|---|---|
| `aes.py` | AES manual (FIPS-197): S-box, key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey beserta inversnya, mode ECB/CBC, padding PKCS#7. Dijalankan sendiri = kalkulator AES. |
| `prng.py` | PRNG Blum Blum Shub (PPT slide 20) untuk session key dan nonce |
| `kdc.py` | Key Distribution Center: langkah 1–2 |
| `alice.py` | Initiator A: langkah 1–5, lalu chat |
| `bob.py` | Responder B: langkah 3–5, lalu chat |
| `channel.py` | Kanal chat AES dua arah (thread terima + kirim) |
| `common.py` | Framing pesan TCP, logging, format field |
| `test_local.py` | Uji otomatis semua skenario di satu mesin |

## Skenario (PPT slide 13)

```
(1) A -> KDC : ID_A || ID_B || N1
(2) KDC -> A : E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])
(3) A -> B   : E(Kb, [Ks || ID_A])
(4) B -> A   : E(Ks, N2)
(5) A -> B   : E(Ks, f(N2))        dengan f(N2) = N2 + 1
```

- **Ka, Kb** adalah *master key*. Ka hanya diketahui Alice dan KDC, Kb hanya diketahui Bob dan KDC.
- **Ks** adalah *session key* baru yang dibuat KDC tiap permintaan dan dipakai untuk chat.
- **N1** mencegah *replay* dari KDC: Alice mengecek N1 yang kembali sama dengan yang ia kirim.
- **N2** dan **f(N2)** adalah tahap autentikasi: membuktikan Alice benar-benar memegang Ks yang sama dan bahwa pesan (3) bukan replay.
- Langkah 1–3 adalah *key distribution steps*, langkah 4–5 adalah *authentication steps*, sesuai label di PPT.

Konkatenasi `||` di kode diwujudkan dengan pemisah `|` (fungsi `pack_fields` di `common.py`).
Ks dibuat dari karakter alfanumerik sehingga tidak bentrok dengan pemisah.

Peta langkah ke kode:

| Langkah | Pengirim (fungsi) | Penerima (fungsi) |
|---|---|---|
| 1 | `Alice.key_distribution` | `KDC.handle` |
| 2 | `KDC.handle` | `Alice.key_distribution` |
| 3 | `Alice.key_distribution` | `Bob.handle` |
| 4 | `Bob.handle` | `Alice.key_distribution` |
| 5 | `Alice.key_distribution` | `Bob.handle` |
| chat | `SecureChannel.send_text` | `SecureChannel._recv_loop` |

## Cara menjalankan (3 perangkat)

Syarat: Python 3.8+ di ketiga perangkat, semuanya di jaringan yang sama (WiFi atau hotspot yang sama).
Cek IP masing-masing dengan `ipconfig` (Windows) atau `ip a` (Linux/macOS).

Misal KDC = `192.168.1.10`, Alice = `192.168.1.11`, Bob = `192.168.1.12`.

```bash
# Perangkat KDC
python kdc.py --port 5000
#   -> isi master key ALICE dan BOB (16/24/32 karakter ASCII)

# Perangkat Bob
python bob.py --port 6000
#   -> isi Kb (harus sama dengan yang didaftarkan di KDC)

# Perangkat Alice
python alice.py --kdc 192.168.1.10:5000 --bob 192.168.1.12:6000
#   -> isi Ka, lalu ketik /connect
```

Setelah `/connect` berhasil, ketik teks apa saja di Alice **atau** Bob untuk mengirim pesan terenkripsi.
Kedua sisi menampilkan plaintext, key, dan ciphertext (hex).

> **Firewall:** KDC dan Bob menerima koneksi masuk. Di Windows, izinkan Python saat muncul prompt firewall,
> atau buka port 5000 dan 6000. Jaringan kampus kadang memblokir koneksi antar-perangkat (*client isolation*),
> jadi lebih aman pakai hotspot HP.

Uji cepat di satu laptop: `python test_local.py`.

## Perintah interaktif (key bisa diubah tanpa restart)

**Alice:** `/connect` (jalankan langkah 1–5; diulang = rekey dengan Ks baru), `/key` (ubah Ka), `/kdc`, `/bob` (ubah alamat),
`/id`, `/peer`, `/mode` (ECB/CBC), `/setks` (ganti session key manual), `/info`, `/help`, `/quit`.

**Bob:** `/key` (ubah Kb), `/id`, `/mode`, `/setks`, `/info`, `/help`, `/quit`.

**KDC (menu angka):** lihat user, tambah/ubah master key, hapus user, panjang session key (16/24/32), mode AES.

**Kalkulator AES:** `python aes.py`. Bisa enkripsi/dekripsi dengan key dan plaintext bebas, self-test FIPS-197,
dan *trace* state tiap round. Berguna kalau dosen minta mencoba test case tertentu.

## Test case untuk demo

| # | Skenario | Hasil yang diharapkan |
|---|---|---|
| 1 | Key benar semua, `/connect` | Langkah 1–5 sukses, chat dua arah jalan |
| 2 | `/connect` lagi | Ks baru (rekey), chat tetap jalan |
| 3 | Ka di Alice beda dengan di KDC | Alice gagal membuka langkah 2 (padding tidak valid) |
| 4 | Kb di Bob beda dengan di KDC | Bob gagal membuka tiket di langkah 3 |
| 5 | `/peer` diisi ID yang tidak terdaftar | KDC menolak di langkah 2 |
| 6 | `/setks` hanya di satu sisi | Penerima gagal dekripsi |
| 7 | `/setks` dengan key yang sama di kedua sisi | Chat kembali normal dengan key baru |
| 8 | Ubah master key di KDC (menu 2) dan di Alice/Bob, lalu `/connect` | Sukses tanpa restart program |
| 9 | Key panjang bukan 16/24/32 | Ditolak dengan pesan error |
| 10 | `python aes.py` → menu 3 | Lulus vektor resmi FIPS-197 |

Contoh verifikasi AES manual (ECB, AES-128):
key `Thats my Kung Fu`, plaintext `Two One Nine Two`, ciphertext `29c3505f571420f6402299b31a02d73a`
(kalkulator menambahkan blok padding, jadi 16 byte pertama yang dicocokkan).

## Wireshark

1. Pilih interface yang dipakai (WiFi/Ethernet; untuk uji di satu laptop pakai *Loopback*).
2. Filter tampilan:
   ```
   tcp.port == 5000 || tcp.port == 6000
   ```
   Atau per perangkat: `ip.addr == 192.168.1.10 && tcp.port == 5000`.
3. Klik paket → *Follow → TCP Stream*. Yang terlihat:
   - Langkah 1: `id_a`, `id_b`, `n1` terbaca jelas (memang plaintext sesuai PPT).
   - Langkah 2–5 dan chat: hanya string **hex**. Ks, master key, dan isi pesan tidak terlihat.

Format paket: 4 byte panjang + JSON, misalnya `{"type": "CHAT", "mode": "CBC", "ct": "2b2aa1..."}`.

## Penjelasan singkat AES

- State 16 byte disusun 4×4 *column-major*. Jumlah round: 10 / 12 / 14 untuk key 16 / 24 / 32 byte.
- **SubBytes:** substitusi tiap byte dengan S-box. S-box tidak di-hardcode, tapi dibangkitkan dari invers perkalian di GF(2⁸) lalu affine transform (`_build_sboxes`).
- **ShiftRows:** baris ke-r digeser ke kiri sebanyak r.
- **MixColumns:** tiap kolom dikalikan matriks `[2 3 1 1]` di GF(2⁸) dengan polinomial `x⁸+x⁴+x³+x+1` (0x11B).
- **AddRoundKey:** XOR state dengan round key.
- **Key expansion:** RotWord, SubWord, dan XOR Rcon tiap Nk word (AES-256 juga SubWord di word ke-4).
- Round terakhir tidak memakai MixColumns. Dekripsi menjalankan invers dengan urutan terbalik.
- **CBC:** tiap blok plaintext di-XOR dengan ciphertext sebelumnya; blok pertama dengan IV acak yang dikirim di depan ciphertext. Jadi plaintext sama menghasilkan ciphertext berbeda.
- **ECB:** blok sama menghasilkan ciphertext sama. Ini terlihat di log langkah 4–5 mode ECB: N2 dan N2+1 memiliki blok pertama ciphertext yang identik.

## Fitur tambahan

1. AES-128/192/256 (session key KDC bisa 16/24/32 karakter).
2. Mode ECB dan CBC (IV acak), bisa diganti saat runtime.
3. Session key dan nonce dari PRNG **Blum Blum Shub** buatan sendiri (Miller-Rabin untuk mencari prima p, q ≡ 3 mod 4).
4. Verifikasi N1 (anti replay dari KDC) dan N2/f(N2) (autentikasi Alice ke Bob).
5. Rekey kapan saja dengan `/connect`, sesuai saran PPT slide 14 bahwa umur session key sebaiknya dibatasi.
6. KDC multi-user dan multi-thread; master key bisa ditambah/diubah saat runtime.
7. Kalkulator AES dengan self-test FIPS-197 dan trace per round.
8. Uji otomatis `test_local.py`.
