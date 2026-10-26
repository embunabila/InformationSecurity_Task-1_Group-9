Pembagian Tugas Cryptography (Della) & Backend (Nayla)

**1. Pembagian tugas:**
  
   Della
   - File crypto_core.py
   - Enkripsi dan dekripsi AES, DES, dan RC4
   - Kunci turunan, salt, IV, dan HMAC
   - Format paket hasil enkripsi dan pengecekannya
   - Tes buat memastikan data bisa balik seperti semula dan perubahan data ditolak
    
    Nayla
    - Login, session, dan pengecekan siapa pemilik data
    - Form profil dan validasi upload
    - Menyiapkan data sebelum dikirim ke fungsi kriptoku
    - Simpan dan baca database/file
    - Upload, download, delete, serta pesan berhasil atau gagal

---

**2. Fungsi encrypt & decrypt:**
   - encrypt
    ``` encrypt_blob(data, master_key, algorithm, context) ```
   - decrypt
    ``` decrypt_blob(envelope, master_key, expected_algorithm, context) ```
   
   - detail:
     - `data` --> Data asli yang sudah kamu ubah jadi bytes
     - `master_key` --> Kunci utama, bytes sepanjang 32 byte 
     - `algorithm` --> Pilih `"AES"`, `"DES"`, atau `"RC4"` 
     - `context` --> Info pemilik dan ID data
     - `envelope` --> Paket hasil enkripsi, juga berupa bytes
     - `expected_algorithm` --> Salinan mana yang ingin kamu buka, misalnya `"AES"`

   - Bytes: bentuk data yang bisa diproses komputer, awalnya dari teks, gambar, dokumen, atau video
   - Hasil encrypt_blob() itu paket terenkripsi, hasil decrypt_blob() data asli dalam bentuk bytes, baru kamu ubah lagi sesuai kebutuhan aplikasi
   - Kalau kamu minta buka AES tapi paketnya ternyata DES, fungsi harus nolak

---

**3. Cara enkripsi dan pemilihan algoritma:**

- Pengguna upload berkas sekali, tanpa milih algoritma
- Nayla nyiapin data sekali, lalu memanggil fungsi enkripsi tiga kali: AES, DES, dan RC4
- Data asli dan context yang dikirim harus sama
- Hasilnya **tiga salinan terpisah**, bukan enkripsi berlapis AES → DES → RC4
- Ketiga enkripsi harus berhasil sebelum penyimpanan dianggap berhasil
- Kalau salah satu gagal, jangan cuma menyimpan dua salinan atau menimpa profil lama

Algoritma yang dipake:

- **AES-256-CBC + HMAC-SHA256**
  - IV acak 16 byte
  - Padding PKCS#7
- **DES-CBC + HMAC-SHA256**
  - IV acak 8 byte
  - Padding PKCS#7
- **RC4 + HMAC-SHA256**
  - Tanpa IV dan padding
  - Tanpa RC4-drop

Pemilihan saat ambil data:

- **Download berkas:** pengguna pilih AES, DES, atau RC4. Pilihan awal AES
- **Baca profil:** menggunakan salinan AES, tanpa pilihan algoritma di tampilan
- Semua salinan harus bisa mengembalikan data asli yang sama persis

Kita nggak pake ECB atau ganti AES ke GCM. DES dan RC4 dipake untuk tugas dan perbandingan, tiga salinan ini bukan berarti keamanan data jadi lebih kuat

---

**4. Master key dan kunci turunan:**

Nayla
- Baca `MASTER_KEY` dari environment
- Bentuknya di environment adalah 64 karakter hex
- Mengubahnya menjadi **32 byte** sebelum dikirim ke fungsi kripto
- Pastiin kuncinya tersedia dan formatnya benar

Aturan:
- Master key dibuat dari angka acak yang sesuai untuk kriptografi, bukan password yang dikarang sendiri
- `MASTER_KEY` berbeda dengan `SECRET_KEY` untuk session Flask
- Jangan membuat master key baru setiap aplikasi dinyalakan
- Kalau master key hilang atau formatnya salah, aplikasi harus gagal mulai, bukan membuat kunci pengganti
- Jangan menaruh kunci asli di kode, GitHub, screenshot, atau chat
- Kalau master key berubah, data lama nggak bisa dibuka dengan kunci baru tanpa proses pemindahan enkripsi


Della
- Menurunkan kunci menggunakan **HKDF-SHA256**.
- Membuat salt acak baru **16 byte untuk setiap envelope**.
- Memisahkan kunci enkripsi dan kunci HMAC.
- Memakai label derivasi berbeda berdasarkan versi, algoritma, dan kegunaannya.

Panjang kunci:

- AES: 32 byte.
- DES: 8 byte.
- RC4: 32 byte.
- HMAC: masing-masing 32 byte.

Nayla nggak perlu bikin salt, IV, atau kunci turunan sendiri

---

**5. Data yang disiapkan sebelum enkripsi:**

**Untuk profil**

- Nayla menggabungkan seluruh field profil menjadi satu JSON
- JSON diubah menjadi UTF-8 bytes
- Field opsional yang kosong tetap `null` di JSON
- Tanggal lahir ikut disimpan dalam data terenkripsi
- Umur nggak disimpan, tetapi dihitung lagi saat profil ditampilkan

**Untuk berkas**

Nayla susun tiga bagian ini urut:

1. Panjang metadata, berupa angka dalam **4 byte unsigned big-endian**
2. Metadata dalam **JSON UTF-8**
3. Isi berkas asli dalam **bytes**

Detail:

- Metadata minimal berisi `filename` dan `mime`.
- Metadata berarti keterangan berkas, seperti nama file dan jenisnya.
- Panjang metadata dihitung berdasarkan jumlah bytes UTF-8, bukan jumlah huruf.
- Big-endian hanya menentukan urutan penulisan angka supaya cara menyusun dan membacanya sama.
- Seluruh gabungan tersebut dienkripsi, sehingga nama file juga ikut tersembunyi.
- Nayla mengemas data sekali, lalu memakai bytes yang sama untuk ketiga cipher.
- Setelah dekripsi berhasil, Nayla mengecek susunannya dan memisahkan kembali metadata serta isi file.
- Nama asli berkas tidak dipakai sebagai path penyimpanan.

---

**6. Context pemilik dan ID data:**

- Context mengikat paket ke pemilik dan item yang benar
- Tujuannya supaya paket akun A nggak bisa ditukar begitu saja dengan paket akun B atau berkas lain
- Context saat enkripsi dan dekripsi harus sama

Isi context:

- `owner_id` → ID pemilik, berupa integer
- `kind` → `"profile"` atau `"file"`, berupa string
- `item_id` → ID item, berupa string

Contoh untuk profil:

```python
context = {
    "owner_id": 7,
    "kind": "profile",
    "item_id": "profile"
}
```

Contoh untuk berkas:

```python
context = {
    "owner_id": 7,
    "kind": "file",
    "item_id": "UUID-berkas"
}
```

Aturannya:

- Angka `7` hanya contoh
- Nayla mengambil pemilik dari session yang sudah diperiksa
- `"UUID-berkas"` diganti dengan ID unik yang dibuat sebelum enkripsi
- Jangan mempercayai ID pemilik dari form atau dari envelope
- Backend tetap wajib memeriksa kepemilikan. Context nggak menggantikan pengecekan akses
- Della mengatur cara context dimasukkan ke HMAC secara konsisten

Batasannya: pengikatan ini belum mencegah pengembalian versi lama dari item yang sama

---

**7. Format hasil enkripsi dan penyimpanan:**

Della
- Mengembalikan satu paket biner utuh, disebut envelope
- Isinya mencakup penanda format/versi, algoritma, salt, IV kalau diperlukan, ciphertext, dan HMAC
- Detail urutan bytes didokumentasikan bersama modul
- Metadata sensitif tidak diletakkan pada header terbuka

Nayla
- Menerima dan menyimpan envelope secara utuh, tanpa membongkar bagian dalamnya

Untuk profil:
- Satu pengguna punya satu baris profil
- Ada tiga kolom SQLite **BLOB**, masing-masing untuk AES, DES, dan RC4
- Ketiga kolom wajib terisi
- Penyimpanan atau pembaruan dilakukan bersama dalam satu transaksi

Untuk berkas:

- Simpan tiga envelope sebagai file biner
- Gunakan folder privat, bukan `static/`
- Nama file penyimpanan berupa nama teknis acak
- Database menyimpan ID, pemilik, kategori, dan lokasi teknis yang diperlukan
- Jangan menyimpan ulang nama asli berkas, MIME, atau isi kesehatan dalam plaintext
- Kalau proses database atau penulisan file gagal, Nayla menangani pembersihan hasil parsial

---

**8. Verifikasi dan penanganan error:**

Della:
1. Periksa struktur dan batas ukuran envelope
2. Verifikasi HMAC
3. Jika berhasil, lakukan dekripsi
4. Lepas padding untuk AES dan DES
5. Kembalikan plaintext

Aturannya:

- HMAC melindungi header, context, dan ciphertext dengan pengemasan yang jelas
- **Tidak ada plaintext yang dikembalikan kalau verifikasi gagal**
- Jangan otomatis mencoba salinan cipher lain jika satu salinan gagal diverifikasi

Error yang disediakan:

- `InvalidEnvelopeError` → Paket tidak valid, berubah, salah kunci/context/algoritma, atau gagal dibuka
- `CryptoConfigError` → Master key tidak tersedia atau tidak valid

Nayla:
- Menangkap dan menangani error yang sesuai.
- Menampilkan pesan umum, misalnya **“Data tidak dapat diverifikasi.”**
- Tidak mengirim plaintext parsial.
- Tidak menampilkan kunci atau isi kesehatan dalam error dan log.

---

**9. Batas ukuran dan cara pemrosesan:**

Batas berkas asli:

- Identitas: JPG, PNG, PDF → maksimal **5 MiB**
- Dokumen: PDF, DOCX → maksimal **10 MiB**
- Video: MP4 → maksimal **25 MiB**

Batas tambahan:

- Metadata maksimal **16 KiB**.
- Payload maksimum: **25 MiB berkas + 16 KiB metadata + 4 byte penanda panjang metadata**
- Della menyediakan batas envelope sesuai tambahan ukuran format kripto
- Nayla tetap memeriksa ukuran dan jenis unggahan di backend
- Batas request upload perlu memperhitungkan bagian form/multipart, bukan hanya ukuran berkas

Cara pemrosesan:

- Seluruh payload diproses di memori
- Belum menggunakan streaming atau pemrosesan per potongan
- Penggunaan RAM bisa lebih besar dari satu file karena ada tiga salinan dan buffer sementara

---

**10. Aturan backend yang tetap wajib:**

- Pengguna harus login sebelum mengakses profil atau arsip
- Periksa pemilik saat baca, edit, download, dan delete
- Semua POST harus memakai pengecekan CSRF
- Kalau penyimpanan profil gagal, profil lama tetap utuh
- Kalau upload gagal sebagian, bersihkan hasil parsial secara terkendali
- Delete menangani ketiga salinan dan record database
- Aktifkan foreign key pada koneksi SQLite yang memakai relasi tersebut
- Jangan menyimpan plaintext sementara di disk, database, session, atau log

---

**11. Urutan pengerjaan dan pengujian:**

**Sambil Della mengerjakan kripto**

- Nayla bisa menyiapkan payload, database, validasi, dan route.
- Jangan membuat fungsi kripto pengganti atau menyimpan plaintext supaya fitur terlihat sudah berjalan.
- Jangan menganggap fungsi selesai sebelum modul dan hasil tes tersedia.

**Target integrasi pertama**

Login → isi profil → enkripsi tiga salinan → simpan → buka kembali melalui AES.

Setelah profil berhasil, lanjutkan fitur arsip.

**Yang diserahkan Della**

- `crypto_core.py`.
- Contoh pemanggilan fungsi.
- Tes dan hasil pengujian nyata.

Tes kripto minimal:

- Semua cipher mengembalikan bytes yang sama persis.
- Mencakup data biner dan ukuran sekitar batas blok.
- Salah kunci, context, atau algoritma ditolak.
- Perubahan header, ciphertext, atau HMAC ditolak.
- Paket terpotong atau tidak valid ditolak.
- Format lama tanpa HMAC ditolak oleh jalur dekripsi baru.
- Enkripsi berulang menghasilkan envelope berbeda, tetapi mengembalikan data asli yang sama.

**Yang diuji Nayla**

- Akses dengan dua akun berbeda.
- CSRF.
- Simpan dan update profil.
- Upload, download, dan delete.
- Kegagalan salah satu salinan.
- Penanganan penyimpanan parsial.

Kalau ada kontrak yang perlu diubah, koordinasikan dulu sebelum mengubah kode yang dipakai bagian lain. Commit, push, PR, dan merge tetap dijalankan sendiri secara manual oleh anggota kelompok.