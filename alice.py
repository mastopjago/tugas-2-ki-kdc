"""
alice.py - Initiator A.

Menjalankan seluruh skenario PPT slide 13 dari sisi Alice:

  (1) A -> KDC : ID_A || ID_B || N1
  (2) KDC -> A : E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])
                 A membuka bagian pertama dengan Ka, cek ID_B dan N1
  (3) A -> B   : E(Kb, [Ks || ID_A])   (tiket diteruskan apa adanya)
  (4) B -> A   : E(Ks, N2)
  (5) A -> B   : E(Ks, f(N2)),  f(N2) = N2 + 1

Setelah itu Alice dan Bob chat dua arah dengan AES memakai Ks.

Pemakaian:  python alice.py --kdc IP_KDC:5000 --bob IP_BOB:6000 [--id ALICE] [--peer BOB]
Perintah di konsol: ketik /help
"""

import argparse
import socket

from aes import AES, validate_key
from channel import SecureChannel
from common import log, parse_addr, recv_msg, send_msg, unpack_fields, valid_id
from prng import BlumBlumShub


def f(n):
    return n + 1


class Alice:
    def __init__(self, kdc_addr, bob_addr, my_id="ALICE", peer_id="BOB"):
        self.kdc_addr = kdc_addr
        self.bob_addr = bob_addr
        self.my_id = my_id
        self.peer_id = peer_id
        self.master_key = None          # Ka
        self.mode = "CBC"
        self.channel = None
        self.bbs = BlumBlumShub()

    def key_distribution(self):
        if self.master_key is None:
            raise ValueError("master key Ka belum diatur")

        # ---------------- langkah 1 & 2: minta session key ke KDC
        n1 = self.bbs.nonce()
        with socket.create_connection(self.kdc_addr, timeout=10) as s:
            send_msg(s, {"step": 1, "id_a": self.my_id, "id_b": self.peer_id, "n1": str(n1)})
            log("ALICE", f"(1) -> KDC {self.kdc_addr[0]}: ID_A={self.my_id}, ID_B={self.peer_id}, N1={n1}")
            resp = recv_msg(s)
        if not resp or "error" in resp:
            raise ValueError(f"KDC menolak: {resp.get('error') if resp else 'tidak ada respon'}")
        log("ALICE", f"(2) <- KDC: E(Ka,...) = {resp['for_a']}")
        log("ALICE", f"(2) <- KDC: tiket E(Kb,...) = {resp['ticket']}")

        try:
            plain = AES(self.master_key).decrypt(resp["for_a"], resp["mode"])
            ks, id_a, id_b, n1_back = unpack_fields(plain, 4)
        except ValueError as e:
            raise ValueError(f"gagal membuka balasan KDC dengan Ka ({e})")
        if id_a != self.my_id or id_b != self.peer_id or n1_back != str(n1):
            raise ValueError("ID atau N1 tidak cocok -> balasan palsu/replay, dibatalkan")
        log("ALICE", f"(2) dibuka dengan Ka: Ks={ks!r}, ID_B={id_b}, N1={n1_back} (cocok)")

        # ---------------- langkah 3: teruskan tiket ke Bob
        sock = socket.create_connection(self.bob_addr, timeout=15)
        try:
            send_msg(sock, {"step": 3, "mode": resp["mode"], "ticket": resp["ticket"]})
            log("ALICE", f"(3) -> BOB {self.bob_addr[0]}: tiket diteruskan")

            # ---------------- langkah 4: terima E(Ks, N2)
            msg4 = recv_msg(sock)
            if not msg4 or "error" in msg4:
                raise ValueError(f"Bob menolak: {msg4.get('error') if msg4 else 'tidak ada respon'}")
            n2 = int(AES(ks).decrypt(msg4["data"], msg4["mode"]))
            log("ALICE", f"(4) <- BOB: E(Ks,N2) = {msg4['data']} -> N2={n2}")

            # ---------------- langkah 5: kirim E(Ks, f(N2))
            data5 = AES(ks).encrypt(str(f(n2)), self.mode)
            send_msg(sock, {"step": 5, "mode": self.mode, "data": data5})
            log("ALICE", f"(5) -> BOB: f(N2)={f(n2)} -> E(Ks,f(N2)) = {data5}")

            ack = recv_msg(sock)
            if not ack or ack.get("type") != "AUTH_OK":
                raise ValueError("Bob tidak mengonfirmasi autentikasi")
        except Exception:
            sock.close()
            raise

        sock.settimeout(None)
        if self.channel:
            self.channel.close()
        self.channel = SecureChannel(sock, ks, self.mode, self.my_id, self.peer_id)
        self.channel.start()
        log("ALICE", f"Key distribution SELESAI. Kanal AES aktif dengan {self.peer_id} (Ks={ks!r}).")


HELP = """Perintah Alice:
  <teks>    kirim pesan terenkripsi ke Bob
  /connect  jalankan key distribution langkah 1-5 (ulang = rekey, Ks baru)
  /key      ubah master key Ka
  /id       ubah ID Alice      /peer   ubah ID tujuan (Bob)
  /kdc      ubah alamat KDC    /bob    ubah alamat Bob
  /mode     ubah mode AES (ECB/CBC)
  /setks    ganti session key secara manual (uji key salah/beda)
  /info     tampilkan status
  /help     bantuan
  /quit     keluar"""


def console(alice):
    print(HELP)
    while True:
        line = input()
        cmd = line.strip()
        try:
            if cmd == "/quit":
                break
            elif cmd == "/help":
                print(HELP)
            elif cmd == "/connect":
                alice.key_distribution()
            elif cmd == "/key":
                k = input("Master key Ka baru (ASCII 16/24/32 char): ")
                validate_key(k)
                alice.master_key = k
                print("  Ka diperbarui. Pastikan KDC memakai key yang sama.")
            elif cmd in ("/id", "/peer"):
                new_id = input("ID baru: ").strip()
                if not valid_id(new_id):
                    raise ValueError("ID harus alfanumerik")
                if cmd == "/id":
                    alice.my_id = new_id
                else:
                    alice.peer_id = new_id
            elif cmd == "/kdc":
                alice.kdc_addr = parse_addr(input("Alamat KDC (IP:port): "), 5000)
            elif cmd == "/bob":
                alice.bob_addr = parse_addr(input("Alamat Bob (IP:port): "), 6000)
            elif cmd == "/mode":
                m = input("Mode (ECB/CBC): ").strip().upper()
                if m not in ("ECB", "CBC"):
                    raise ValueError("harus ECB atau CBC")
                alice.mode = m
                if alice.channel:
                    alice.channel.mode = m
            elif cmd == "/setks":
                if not alice.channel:
                    raise ValueError("belum ada sesi")
                k = input("Session key baru (ASCII 16/24/32 char): ")
                validate_key(k)
                alice.channel.session_key = k
                print("  Session key lokal diganti (sisi lawan harus ganti juga).")
            elif cmd == "/info":
                ch = alice.channel
                print(f"  ID={alice.my_id} -> {alice.peer_id} | Ka={alice.master_key!r} | mode={alice.mode}")
                print(f"  KDC={alice.kdc_addr[0]}:{alice.kdc_addr[1]} | Bob={alice.bob_addr[0]}:{alice.bob_addr[1]}")
                if ch and ch.alive:
                    print(f"  Sesi aktif: Ks={ch.session_key!r}, kirim={ch.sent}, terima={ch.received}")
                else:
                    print("  Belum ada sesi aktif (jalankan /connect).")
            elif cmd.startswith("/"):
                print("  Perintah tidak dikenal. Ketik /help")
            elif line:
                if not alice.channel or not alice.channel.alive:
                    raise ValueError("belum ada sesi; jalankan /connect dulu")
                alice.channel.send_text(line)
        except (ValueError, OSError) as e:
            print("  Error:", e)


def main():
    ap = argparse.ArgumentParser(description="Initiator A")
    ap.add_argument("--kdc", required=True, help="IP_KDC:port, mis. 192.168.1.10:5000")
    ap.add_argument("--bob", required=True, help="IP_BOB:port, mis. 192.168.1.12:6000")
    ap.add_argument("--id", default="ALICE")
    ap.add_argument("--peer", default="BOB")
    args = ap.parse_args()

    alice = Alice(parse_addr(args.kdc, 5000), parse_addr(args.bob, 6000), args.id, args.peer)
    while alice.master_key is None:
        k = input(f"Master key {alice.my_id} / Ka (ASCII 16/24/32 char): ")
        try:
            validate_key(k)
            alice.master_key = k
        except ValueError as e:
            print("  Error:", e)
    try:
        console(alice)
    except (KeyboardInterrupt, EOFError):
        pass
    print("Alice berhenti.")


if __name__ == "__main__":
    main()
