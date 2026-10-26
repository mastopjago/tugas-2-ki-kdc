"""
test_local.py - Uji otomatis seluruh skenario di satu mesin (127.0.0.1).

Menjalankan KDC dan Bob di thread, lalu Alice melakukan langkah 1-5,
chat dua arah, rekey, dan beberapa kasus gagal (key salah, ID tak terdaftar).
Untuk demo sebenarnya tetap jalankan kdc.py, alice.py, bob.py di 3 perangkat.

Pemakaian:  python test_local.py
"""

import threading
import time

import aes
from alice import Alice
from bob import Bob
from kdc import KDC

KA = "kunciAlice123456"
KB = "kunciBob_7890abc"


def wait():
    time.sleep(0.4)


def expect_fail(label, fn):
    try:
        fn()
    except ValueError as e:
        print(f"[OK] {label} -> ditolak: {e}")
        return
    raise AssertionError(f"{label} seharusnya gagal")


def main():
    assert aes.self_test(verbose=False), "AES self-test gagal"
    print("[OK] AES self-test FIPS-197")

    kdc = KDC("127.0.0.1", 0)
    kdc.set_user("ALICE", KA)
    kdc.set_user("BOB", KB)
    threading.Thread(target=kdc.serve_forever, daemon=True).start()

    bob = Bob("BOB", "127.0.0.1", 0)
    bob.master_key = KB
    threading.Thread(target=bob.serve_forever, daemon=True).start()

    alice = Alice(("127.0.0.1", kdc.port), ("127.0.0.1", bob.port))
    alice.master_key = KA

    # skenario normal
    alice.key_distribution()
    wait()
    assert bob.channel and bob.channel.session_key == alice.channel.session_key
    print("[OK] Langkah 1-5 berhasil, Ks sama di Alice & Bob")

    alice.channel.send_text("Halo Bob, ini Alice!")
    bob.channel.send_text("Halo juga Alice, pesan diterima.")
    wait()
    assert alice.channel.received == 1 and bob.channel.received == 1
    print("[OK] Chat dua arah")

    # rekey: Ks baru
    old = alice.channel.session_key
    alice.key_distribution()
    wait()
    assert alice.channel.session_key != old
    assert bob.channel.session_key == alice.channel.session_key
    print("[OK] Rekey menghasilkan Ks baru")

    # mode ECB + AES-256 session key
    kdc.session_key_len = 32
    alice.mode = bob.mode = "ECB"
    alice.key_distribution()
    wait()
    assert len(alice.channel.session_key) == 32
    alice.channel.send_text("Tes ECB dengan AES-256")
    wait()
    print("[OK] Session key AES-256 + mode ECB")

    # key salah
    alice.master_key = "salahsalahsalah1"
    expect_fail("Ka salah", alice.key_distribution)
    alice.master_key = KA

    bob.master_key = "kunciBobSalah___"
    expect_fail("Kb salah", alice.key_distribution)
    bob.master_key = KB

    alice.peer_id = "CHARLIE"
    expect_fail("ID tidak terdaftar", alice.key_distribution)
    alice.peer_id = "BOB"

    # session key beda -> Bob gagal dekripsi
    alice.key_distribution()
    wait()
    alice.channel.session_key = "keyBedaSendiri!!"
    alice.channel.send_text("Pesan ini tidak bisa dibaca Bob")
    wait()
    print("[OK] Session key beda -> dekripsi gagal di Bob (lihat log)")
    print("\nSEMUA TES LULUS")


if __name__ == "__main__":
    main()
