"""
channel.py - Kanal chat terenkripsi AES (dipakai setelah langkah 5 selesai).

Alice dan Bob memakai kelas yang sama, sehingga keduanya bisa menjadi
SENDER maupun RECEIVER: thread penerima berjalan di latar belakang,
sementara thread utama membaca input dan mengirim pesan.
"""

import threading

from aes import AES
from common import log, recv_msg, send_msg


class SecureChannel:
    def __init__(self, sock, session_key, mode, my_id, peer_id):
        self.sock = sock
        self.session_key = session_key
        self.mode = mode
        self.my_id = my_id
        self.peer_id = peer_id
        self.alive = True
        self.sent = 0
        self.received = 0

    def start(self):
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def send_text(self, text):
        cipher_hex = AES(self.session_key).encrypt(text, self.mode)
        send_msg(self.sock, {"type": "CHAT", "mode": self.mode, "ct": cipher_hex})
        self.sent += 1
        log("KIRIM", f"{self.my_id} -> {self.peer_id} | plaintext : {text}")
        log("KIRIM", f"key={self.session_key!r} mode={self.mode} | ciphertext (hex): {cipher_hex}")

    def _recv_loop(self):
        try:
            while self.alive:
                msg = recv_msg(self.sock)
                if msg is None:
                    break
                if msg.get("type") != "CHAT":
                    continue
                cipher_hex, mode = msg["ct"], msg.get("mode", "CBC")
                self.received += 1
                log("TERIMA", f"{self.peer_id} -> {self.my_id} | ciphertext (hex): {cipher_hex}")
                try:
                    plain = AES(self.session_key).decrypt(cipher_hex, mode)
                    log("TERIMA", f"key={self.session_key!r} mode={mode} | plaintext : {plain}")
                except ValueError as e:
                    log("TERIMA", f"GAGAL dekripsi dengan key={self.session_key!r}: {e}")
        except (OSError, ValueError):
            pass
        if self.alive:
            log("INFO", f"Koneksi dengan {self.peer_id} terputus.")
        self.alive = False

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass
