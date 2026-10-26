"""
common.py - Utilitas bersama: framing pesan TCP, logging, dan format field.

Setiap pesan dikirim sebagai: [4 byte panjang (big-endian)] + [JSON ASCII].
Field terenkripsi di dalam JSON selalu berupa string hex, jadi di Wireshark
yang terlihat hanya hex ciphertext, bukan plaintext/key.
"""

import json
import socket
import struct
import threading
import time

SEP = "|"            # pemisah field '||' (konkatenasi) di dalam plaintext
MAX_MSG = 1_000_000

_print_lock = threading.Lock()


def log(tag, msg):
    with _print_lock:
        print(f"[{time.strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)


def send_msg(sock, obj):
    data = json.dumps(obj).encode("ascii")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_msg(sock):
    """Mengembalikan dict, atau None bila koneksi tertutup."""
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length > MAX_MSG:
        raise ValueError("pesan terlalu besar")
    body = _recv_exact(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("ascii"))


def pack_fields(*fields):
    """Konkatenasi A || B || C  ->  'A|B|C'."""
    parts = [str(f) for f in fields]
    for p in parts:
        if SEP in p:
            raise ValueError(f"field tidak boleh mengandung '{SEP}'")
    return SEP.join(parts)


def unpack_fields(text, count):
    parts = text.split(SEP)
    if len(parts) != count:
        raise ValueError(f"format pesan salah (harap {count} field, dapat {len(parts)})")
    return parts


def valid_id(s):
    return s.isascii() and s.isalnum() and 1 <= len(s) <= 32


def parse_addr(text, default_port):
    """'192.168.1.5:5000' atau '192.168.1.5' -> (host, port)."""
    host, _, port = text.strip().partition(":")
    return host, int(port) if port else default_port


def local_ip():
    """IP LAN perangkat ini (hanya untuk ditampilkan)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"
