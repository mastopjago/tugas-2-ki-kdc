"""
bob.py - Responder B.

Menangani langkah (3), (4), (5) dari skenario PPT slide 13:

  (3) A -> B : E(Kb, [Ks || ID_A])     B membuka tiket dengan master key Kb
  (4) B -> A : E(Ks, N2)               B menantang A dengan nonce N2
  (5) A -> B : E(Ks, f(N2))            B memeriksa f(N2) = N2 + 1

Setelah langkah 5 valid, Bob dan Alice chat dua arah dengan AES memakai Ks.

Pemakaian:  python bob.py [--port 6000] [--id BOB]
Perintah di konsol: ketik /help
"""

import argparse
import socket
import threading

from aes import AES, validate_key
from channel import SecureChannel
from common import local_ip, log, recv_msg, send_msg, unpack_fields, valid_id
from prng import BlumBlumShub


def f(n):
    """Fungsi transformasi nonce pada langkah 5."""
    return n + 1


class Bob:
    def __init__(self, my_id="BOB", host="0.0.0.0", port=6000):
        self.my_id = my_id
        self.master_key = None          # Kb
        self.mode = "CBC"
        self.channel = None
        self.lock = threading.Lock()
        self.bbs = BlumBlumShub()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]

    def serve_forever(self):
        log("BOB", f"Mendengarkan di {local_ip()}:{self.port}")
        while True:
            try:
                conn, addr = self.server.accept()
            except OSError:
                break
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        try:
            conn.settimeout(15)
            # ---------------- langkah 3: terima tiket dari Alice
            msg = recv_msg(conn)
            if not msg or msg.get("step") != 3:
                raise ValueError("pesan langkah 3 tidak valid")
            log("BOB", f"(3) dari {addr[0]}: tiket = {msg['ticket']}")
            if self.master_key is None:
                raise ValueError("master key Kb belum diatur")
            try:
                plain = AES(self.master_key).decrypt(msg["ticket"], msg.get("mode", "CBC"))
                ks, id_a = unpack_fields(plain, 2)
                validate_key(ks)
            except ValueError as e:
                raise ValueError(f"tiket tidak bisa dibuka dengan Kb ({e})")
            log("BOB", f"(3) tiket dibuka: Ks={ks!r}, ID_A={id_a}")

            # ---------------- langkah 4: kirim tantangan E(Ks, N2)
            n2 = self.bbs.nonce()
            data4 = AES(ks).encrypt(str(n2), self.mode)
            send_msg(conn, {"step": 4, "mode": self.mode, "data": data4})
            log("BOB", f"(4) N2={n2} -> E(Ks,N2) = {data4}")

            # ---------------- langkah 5: verifikasi E(Ks, f(N2))
            msg5 = recv_msg(conn)
            if not msg5 or msg5.get("step") != 5:
                raise ValueError("pesan langkah 5 tidak valid")
            answer = AES(ks).decrypt(msg5["data"], msg5.get("mode", "CBC"))
            log("BOB", f"(5) E(Ks,f(N2)) = {msg5['data']} -> {answer}")
            if answer != str(f(n2)):
                send_msg(conn, {"type": "AUTH_FAIL", "reason": "f(N2) salah"})
                raise ValueError(f"autentikasi gagal: harap {f(n2)}, dapat {answer}")
            send_msg(conn, {"type": "AUTH_OK", "id": self.my_id})
            log("BOB", f"Autentikasi {id_a} BERHASIL. Kanal AES aktif (Ks={ks!r}).")

            conn.settimeout(None)
            with self.lock:
                if self.channel:
                    self.channel.close()
                self.channel = SecureChannel(conn, ks, self.mode, self.my_id, id_a)
                self.channel.start()
        except (OSError, ValueError, KeyError) as e:
            log("BOB", f"Handshake gagal: {e}")
            try:
                send_msg(conn, {"step": 4, "error": str(e)})
            except OSError:
                pass
            conn.close()


HELP = """Perintah Bob:
  <teks>    kirim pesan terenkripsi ke Alice
  /key      ubah master key Kb
  /id       ubah ID Bob
  /mode     ubah mode AES (ECB/CBC)
  /setks    ganti session key secara manual (uji key salah/beda)
  /info     tampilkan status
  /help     bantuan
  /quit     keluar"""


def console(bob):
    print(HELP)
    while True:
        line = input()
        cmd = line.strip()
        try:
            if cmd == "/quit":
                break
            elif cmd == "/help":
                print(HELP)
            elif cmd == "/key":
                k = input("Master key Kb baru (ASCII 16/24/32 char): ")
                validate_key(k)
                bob.master_key = k
                print("  Kb diperbarui. Pastikan KDC memakai key yang sama.")
            elif cmd == "/id":
                new_id = input("ID baru: ").strip()
                if not valid_id(new_id):
                    raise ValueError("ID harus alfanumerik")
                bob.my_id = new_id
            elif cmd == "/mode":
                m = input("Mode (ECB/CBC): ").strip().upper()
                if m not in ("ECB", "CBC"):
                    raise ValueError("harus ECB atau CBC")
                bob.mode = m
                if bob.channel:
                    bob.channel.mode = m
            elif cmd == "/setks":
                if not bob.channel:
                    raise ValueError("belum ada sesi")
                k = input("Session key baru (ASCII 16/24/32 char): ")
                validate_key(k)
                bob.channel.session_key = k
                print("  Session key lokal diganti (sisi lawan harus ganti juga).")
            elif cmd == "/info":
                ch = bob.channel
                print(f"  ID={bob.my_id} | Kb={bob.master_key!r} | mode={bob.mode} | port={bob.port}")
                if ch and ch.alive:
                    print(f"  Sesi dengan {ch.peer_id}: Ks={ch.session_key!r}, kirim={ch.sent}, terima={ch.received}")
                else:
                    print("  Belum ada sesi aktif.")
            elif cmd.startswith("/"):
                print("  Perintah tidak dikenal. Ketik /help")
            elif line:
                if not bob.channel or not bob.channel.alive:
                    raise ValueError("belum ada sesi; tunggu Alice menjalankan key distribution")
                bob.channel.send_text(line)
        except (ValueError, OSError) as e:
            print("  Error:", e)


def main():
    ap = argparse.ArgumentParser(description="Responder B")
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--id", default="BOB")
    args = ap.parse_args()

    bob = Bob(args.id, port=args.port)
    while bob.master_key is None:
        k = input(f"Master key {bob.my_id} / Kb (ASCII 16/24/32 char): ")
        try:
            validate_key(k)
            bob.master_key = k
        except ValueError as e:
            print("  Error:", e)
    threading.Thread(target=bob.serve_forever, daemon=True).start()
    try:
        console(bob)
    except (KeyboardInterrupt, EOFError):
        pass
    print("Bob berhenti.")


if __name__ == "__main__":
    main()
