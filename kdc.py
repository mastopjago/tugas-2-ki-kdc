"""
kdc.py - Key Distribution Center (manual).

Menangani langkah (1) dan (2) dari skenario PPT slide 13:

  (1) A -> KDC : ID_A || ID_B || N1                                   (plaintext)
  (2) KDC -> A : E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])

KDC menyimpan master key tiap user (Ka untuk Alice, Kb untuk Bob), dan
membangkitkan session key Ks baru (dengan PRNG Blum Blum Shub) setiap ada
permintaan. Master key bisa ditambah/diubah dari menu tanpa restart.

Pemakaian:  python kdc.py [--port 5000]
"""

import argparse
import socket
import threading

from aes import AES, validate_key
from common import local_ip, log, pack_fields, recv_msg, send_msg, valid_id
from prng import BlumBlumShub


class KDC:
    def __init__(self, host="0.0.0.0", port=5000):
        self.users = {}                 # ID -> master key (ASCII)
        self.session_key_len = 16
        self.mode = "CBC"
        self.lock = threading.Lock()
        log("KDC", "Menyiapkan PRNG Blum Blum Shub...")
        self.bbs = BlumBlumShub()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]

    # ------------------------------------------------------------------ server
    def serve_forever(self):
        log("KDC", f"Mendengarkan di {local_ip()}:{self.port}")
        while True:
            try:
                conn, addr = self.server.accept()
            except OSError:
                break
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        with conn:
            try:
                msg = recv_msg(conn)
                if not msg or msg.get("step") != 1:
                    send_msg(conn, {"step": 2, "error": "pesan langkah 1 tidak valid"})
                    return
                id_a, id_b, n1 = str(msg["id_a"]), str(msg["id_b"]), str(msg["n1"])
                log("KDC", f"(1) dari {addr[0]}: ID_A={id_a}, ID_B={id_b}, N1={n1}")

                if not (valid_id(id_a) and valid_id(id_b) and n1.isdigit()):
                    send_msg(conn, {"step": 2, "error": "ID/nonce tidak valid"})
                    return
                with self.lock:
                    ka, kb = self.users.get(id_a), self.users.get(id_b)
                    mode, ks_len = self.mode, self.session_key_len
                    if ka is None or kb is None:
                        missing = id_a if ka is None else id_b
                        log("KDC", f"Ditolak: ID {missing} tidak terdaftar")
                        send_msg(conn, {"step": 2, "error": f"ID {missing} tidak terdaftar di KDC"})
                        return
                    ks = self.bbs.random_string(ks_len)     # session key baru

                for_a = AES(ka).encrypt(pack_fields(ks, id_a, id_b, n1), mode)
                ticket = AES(kb).encrypt(pack_fields(ks, id_a), mode)
                send_msg(conn, {"step": 2, "mode": mode, "for_a": for_a, "ticket": ticket})

                log("KDC", f"Session key Ks dibuat: {ks!r} (AES-{ks_len * 8}, mode {mode})")
                log("KDC", f"(2) E(Ka,[Ks||ID_A||ID_B||N1]) = {for_a}")
                log("KDC", f"(2) E(Kb,[Ks||ID_A])           = {ticket}")
            except (OSError, ValueError, KeyError) as e:
                log("KDC", f"Error menangani {addr[0]}: {e}")

    # -------------------------------------------------------------- pengaturan
    def set_user(self, user_id, key):
        if not valid_id(user_id):
            raise ValueError("ID harus alfanumerik 1-32 karakter")
        validate_key(key)
        with self.lock:
            self.users[user_id] = key

    def menu(self):
        while True:
            print("\n===== MENU KDC =====")
            print("1) Lihat user & master key   2) Tambah/ubah master key")
            print("3) Hapus user                4) Panjang session key (16/24/32)")
            print("5) Mode AES (ECB/CBC)        0) Keluar")
            choice = input("Pilih: ").strip()
            try:
                if choice == "1":
                    with self.lock:
                        if not self.users:
                            print("  (belum ada user)")
                        for uid, key in self.users.items():
                            print(f"  {uid:<12} {key!r}")
                        print(f"  Session key: {self.session_key_len} char | Mode: {self.mode}")
                elif choice == "2":
                    uid = input("ID user: ").strip()
                    key = input("Master key (ASCII 16/24/32 char): ")
                    self.set_user(uid, key)
                    print(f"  Master key {uid} disimpan.")
                elif choice == "3":
                    uid = input("ID user: ").strip()
                    with self.lock:
                        print("  Dihapus." if self.users.pop(uid, None) else "  Tidak ditemukan.")
                elif choice == "4":
                    n = int(input("Panjang (16/24/32): ").strip())
                    if n not in (16, 24, 32):
                        raise ValueError("harus 16, 24, atau 32")
                    with self.lock:
                        self.session_key_len = n
                elif choice == "5":
                    m = input("Mode (ECB/CBC): ").strip().upper()
                    if m not in ("ECB", "CBC"):
                        raise ValueError("harus ECB atau CBC")
                    with self.lock:
                        self.mode = m
                elif choice == "0":
                    break
            except ValueError as e:
                print("  Error:", e)


def main():
    ap = argparse.ArgumentParser(description="Key Distribution Center")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    kdc = KDC(port=args.port)
    print("Daftarkan master key Alice dan Bob (bisa diubah lagi lewat menu).")
    for default_id in ("ALICE", "BOB"):
        while True:
            uid = input(f"ID user [{default_id}]: ").strip() or default_id
            key = input(f"Master key {uid} (ASCII 16/24/32 char): ")
            try:
                kdc.set_user(uid, key)
                break
            except ValueError as e:
                print("  Error:", e)

    threading.Thread(target=kdc.serve_forever, daemon=True).start()
    try:
        kdc.menu()
    except (KeyboardInterrupt, EOFError):
        pass
    print("KDC berhenti.")


if __name__ == "__main__":
    main()
