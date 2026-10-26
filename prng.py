"""
prng.py - Blum Blum Shub (BBS) PRNG, dibuat manual (lihat PPT slide 20).

    x_i = x_{i-1}^2 mod n,  n = p*q,  p dan q prima dengan p = q = 3 (mod 4)
    output = bit paling tidak signifikan (LSB) dari x_i

Dipakai KDC untuk membangkitkan session key Ks, dan dipakai Alice/Bob untuk
membangkitkan nonce N1 dan N2. Keamanannya bersandar pada sulitnya memfaktorkan n.
Seed awal diambil dari sumber acak OS (modul secrets).
"""

import secrets
from math import gcd

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def is_probable_prime(n, rounds=40):
    """Uji primalitas Miller-Rabin."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_blum_prime(bits):
    """Prima p dengan p mod 4 == 3 (dua bit terendah = 11)."""
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 0b11
        if is_probable_prime(p):
            return p


class BlumBlumShub:
    def __init__(self, bits=256):
        p = gen_blum_prime(bits)
        q = gen_blum_prime(bits)
        while q == p:
            q = gen_blum_prime(bits)
        self.n = p * q            # p dan q tidak disimpan
        while True:
            seed = secrets.randbelow(self.n - 2) + 2
            if gcd(seed, self.n) == 1:
                break
        self.x = pow(seed, 2, self.n)

    def next_bit(self):
        self.x = pow(self.x, 2, self.n)
        return self.x & 1

    def next_bits(self, k):
        v = 0
        for _ in range(k):
            v = (v << 1) | self.next_bit()
        return v

    def randbelow(self, m):
        """Bilangan acak seragam di [0, m) dengan rejection sampling."""
        k = max(1, (m - 1).bit_length())
        while True:
            v = self.next_bits(k)
            if v < m:
                return v

    def nonce(self, bits=64):
        return self.next_bits(bits)

    def random_string(self, length, alphabet=ALNUM):
        return "".join(alphabet[self.randbelow(len(alphabet))] for _ in range(length))


if __name__ == "__main__":
    g = BlumBlumShub()
    print("n (bit) =", g.n.bit_length())
    print("nonce   =", g.nonce())
    print("key 16  =", g.random_string(16))
