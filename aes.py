"""
aes.py - Implementasi AES MANUAL (FIPS-197), tanpa library kriptografi.

Mendukung:
  - AES-128 / AES-192 / AES-256 (key ASCII 16 / 24 / 32 karakter)
  - Mode ECB dan CBC (CBC: IV acak 16 byte ditaruh di depan ciphertext)
  - Padding PKCS#7
  - Input key & plaintext: ASCII, output ciphertext: hexadecimal

Representasi state: list 16 byte, column-major (seperti di FIPS-197):
  state[r + 4*c] = baris r, kolom c
  byte input ke-i  -> baris i % 4, kolom i // 4

Jalankan `python aes.py` untuk kalkulator AES interaktif (enkripsi/dekripsi,
self-test vektor FIPS-197, dan trace per-round).
"""

import secrets

BLOCK_SIZE = 16
ROUNDS_BY_KEYLEN = {16: 10, 24: 12, 32: 14}   # Nk*4 byte -> Nr


# ---------------------------------------------------------------------------
# Aritmetika GF(2^8) dengan polinomial irreducible x^8 + x^4 + x^3 + x + 1
# ---------------------------------------------------------------------------
def gmul(a, b):
    """Perkalian dua byte di GF(2^8) (metode 'russian peasant')."""
    p = 0
    while b:
        if b & 1:
            p ^= a
        # xtime: kali 2; jika bit 7 keluar, reduksi dengan 0x1B
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)
        b >>= 1
    return p


def _rotl8(x, s):
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _build_sboxes():
    """S-box dibangkitkan sendiri: invers multiplikatif GF(2^8) + affine transform."""
    sbox, inv_sbox = [0] * 256, [0] * 256
    for x in range(256):
        inv = 0
        if x:
            for c in range(1, 256):
                if gmul(x, c) == 1:
                    inv = c
                    break
        s = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        sbox[x] = s
        inv_sbox[s] = x
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sboxes()

# Tabel perkalian untuk MixColumns (mempercepat; isinya tetap hasil gmul)
MUL2 = [gmul(i, 2) for i in range(256)]
MUL3 = [gmul(i, 3) for i in range(256)]
MUL9 = [gmul(i, 9) for i in range(256)]
MUL11 = [gmul(i, 11) for i in range(256)]
MUL13 = [gmul(i, 13) for i in range(256)]
MUL14 = [gmul(i, 14) for i in range(256)]


# ---------------------------------------------------------------------------
# Key Expansion
# ---------------------------------------------------------------------------
def key_expansion(key: bytes):
    """Menghasilkan Nr+1 round key (masing-masing 16 byte)."""
    nk = len(key) // 4
    nr = ROUNDS_BY_KEYLEN[len(key)]
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 0x01
    for i in range(nk, 4 * (nr + 1)):
        temp = words[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= rcon                         # XOR Rcon
            rcon = gmul(rcon, 2)
        elif nk > 6 and i % nk == 4:                # khusus AES-256
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(nr + 1)]


# ---------------------------------------------------------------------------
# Transformasi round
# ---------------------------------------------------------------------------
def add_round_key(state, rk):
    return [s ^ k for s, k in zip(state, rk)]


def sub_bytes(state):
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def shift_rows(state):
    # baris r digeser ke kiri sebanyak r
    return [state[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(state):
    # baris r digeser ke kanan sebanyak r
    return [state[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def mix_columns(state):
    out = []
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c:4 * c + 4]
        out += [
            MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3,
            a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3,
            a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3],
            MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3],
        ]
    return out


def inv_mix_columns(state):
    out = []
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c:4 * c + 4]
        out += [
            MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3],
            MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3],
            MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3],
            MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3],
        ]
    return out


# ---------------------------------------------------------------------------
# Padding PKCS#7
# ---------------------------------------------------------------------------
def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("data kosong")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("padding tidak valid (kemungkinan key/mode salah)")
    return data[:-n]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Kelas AES
# ---------------------------------------------------------------------------
def validate_key(key: str) -> bytes:
    try:
        kb = key.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("key harus karakter ASCII")
    if len(kb) not in ROUNDS_BY_KEYLEN:
        raise ValueError(f"panjang key harus 16/24/32 karakter (sekarang {len(kb)})")
    return kb


class AES:
    def __init__(self, key: str):
        kb = validate_key(key)
        self.key = key
        self.nr = ROUNDS_BY_KEYLEN[len(kb)]
        self.round_keys = key_expansion(kb)

    # ---- satu blok 16 byte ----
    def encrypt_block(self, block: bytes, trace=None) -> bytes:
        state = add_round_key(list(block), self.round_keys[0])
        if trace is not None:
            trace.append(("Round 0 (AddRoundKey)", bytes(state).hex()))
        for r in range(1, self.nr):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.round_keys[r])
            if trace is not None:
                trace.append((f"Round {r}", bytes(state).hex()))
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, self.round_keys[self.nr])
        if trace is not None:
            trace.append((f"Round {self.nr} (final, tanpa MixColumns)", bytes(state).hex()))
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        state = add_round_key(list(block), self.round_keys[self.nr])
        for r in range(self.nr - 1, 0, -1):
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)
            state = add_round_key(state, self.round_keys[r])
            state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, self.round_keys[0])
        return bytes(state)

    # ---- pesan sembarang panjang ----
    def encrypt(self, plaintext: str, mode: str = "CBC") -> str:
        try:
            data = pkcs7_pad(plaintext.encode("ascii"))
        except UnicodeEncodeError:
            raise ValueError("plaintext harus karakter ASCII")
        mode = mode.upper()
        blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
        if mode == "ECB":
            out = b"".join(self.encrypt_block(b) for b in blocks)
        elif mode == "CBC":
            iv = secrets.token_bytes(BLOCK_SIZE)
            out, prev = iv, iv
            for b in blocks:
                prev = self.encrypt_block(_xor(b, prev))
                out += prev
        else:
            raise ValueError("mode harus ECB atau CBC")
        return out.hex()

    def decrypt(self, cipher_hex: str, mode: str = "CBC") -> str:
        try:
            data = bytes.fromhex(cipher_hex)
        except ValueError:
            raise ValueError("ciphertext bukan hex yang valid")
        mode = mode.upper()
        if mode == "CBC":
            if len(data) < 2 * BLOCK_SIZE:
                raise ValueError("ciphertext CBC terlalu pendek")
            prev, data = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
        elif mode != "ECB":
            raise ValueError("mode harus ECB atau CBC")
        if len(data) == 0 or len(data) % BLOCK_SIZE:
            raise ValueError("panjang ciphertext bukan kelipatan 16 byte")
        out = b""
        for i in range(0, len(data), BLOCK_SIZE):
            c = data[i:i + BLOCK_SIZE]
            p = self.decrypt_block(c)
            if mode == "CBC":
                p, prev = _xor(p, prev), c
            out += p
        out = pkcs7_unpad(out)
        try:
            return out.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("hasil dekripsi bukan ASCII (kemungkinan key salah)")


# ---------------------------------------------------------------------------
# Self-test dengan vektor resmi FIPS-197 Appendix C
# ---------------------------------------------------------------------------
TEST_VECTORS = [
    ("AES-128 (FIPS-197 C.1)", bytes(range(16)), "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("AES-192 (FIPS-197 C.2)", bytes(range(24)), "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("AES-256 (FIPS-197 C.3)", bytes(range(32)), "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
    ("AES-128 ASCII 'Thats my Kung Fu'", b"Thats my Kung Fu", b"Two One Nine Two".hex(), "29c3505f571420f6402299b31a02d73a"),
]


def self_test(verbose=True) -> bool:
    ok_all = True
    for name, key, pt_hex, ct_hex in TEST_VECTORS:
        aes = AES(key.decode("ascii"))
        ct = aes.encrypt_block(bytes.fromhex(pt_hex)).hex()
        pt = aes.decrypt_block(bytes.fromhex(ct)).hex()
        ok = ct == ct_hex and pt == pt_hex
        ok_all &= ok
        if verbose:
            print(f"  [{'OK' if ok else 'GAGAL'}] {name}: {ct}")
    return ok_all


# ---------------------------------------------------------------------------
# Kalkulator AES interaktif
# ---------------------------------------------------------------------------
def _main():
    print("=== Kalkulator AES Manual ===")
    while True:
        print("\n1) Enkripsi  2) Dekripsi  3) Self-test FIPS-197  4) Trace per-round (1 blok, ECB)  0) Keluar")
        choice = input("Pilih: ").strip()
        try:
            if choice == "1":
                key = input("Key (ASCII 16/24/32 char): ")
                mode = input("Mode [ECB/CBC] (default CBC): ").strip() or "CBC"
                pt = input("Plaintext (ASCII): ")
                print("Ciphertext (hex):", AES(key).encrypt(pt, mode))
            elif choice == "2":
                key = input("Key (ASCII 16/24/32 char): ")
                mode = input("Mode [ECB/CBC] (default CBC): ").strip() or "CBC"
                ct = input("Ciphertext (hex): ").strip()
                print("Plaintext:", AES(key).decrypt(ct, mode))
            elif choice == "3":
                print("Semua lulus." if self_test() else "Ada yang gagal!")
            elif choice == "4":
                key = input("Key (ASCII 16/24/32 char): ")
                pt = input("Plaintext maks 16 char (ASCII): ")
                block = pkcs7_pad(pt.encode("ascii"))[:16]
                aes = AES(key)
                print("Round keys:")
                for i, rk in enumerate(aes.round_keys):
                    print(f"  K{i:<2} = {bytes(rk).hex()}")
                trace = []
                aes.encrypt_block(block, trace)
                print("State setelah tiap round:")
                for name, val in trace:
                    print(f"  {name:<40} {val}")
            elif choice == "0":
                break
        except ValueError as e:
            print("Error:", e)


if __name__ == "__main__":
    _main()
