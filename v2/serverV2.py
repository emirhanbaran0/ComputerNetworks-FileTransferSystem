# server.py
import socket
import os
import struct
import hashlib
import logging
import base64
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from scapy.all import sniff, IP, ICMP
from scapy.utils import checksum as scapy_checksum

# ——— Configuration ———
HOST = '0.0.0.0'
PORT = 12346
SECRET_KEY = b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef'
VALID_TOKEN = "C1H4L3"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def recv_prefixed(sock):
    """Read 2-byte length then that many bytes. Returns b'' on zero length."""
    raw = sock.recv(2)
    if not raw:
        return None
    length, = struct.unpack('!H', raw)
    if length == 0:
        return b''
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed mid-recv")
        data += chunk
    return data

def unique_received_path(name, prefix="received_", max_tries=1000):
    path = f"{prefix}{name}"
    tries = 0
    while os.path.exists(path) and tries < max_tries:
        path = f"{prefix}{random.randint(0,9999)}_{name}"
        tries += 1
    if os.path.exists(path):
        raise FileExistsError("Could not find a free filename")
    return path

def reassemble(fragments, total_len):
    buf = bytearray(total_len)
    for off, chunk in fragments.items():
        buf[off:off+len(chunk)] = chunk
    return bytes(buf)

def start_server():
    ctl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctl.bind((HOST, PORT))
    ctl.listen(1)
    logging.info("Waiting for control connection…")
    conn, addr = ctl.accept()
    logging.info(f"Control from {addr}")

    token = recv_prefixed(conn)
    if token is None or token.decode() != VALID_TOKEN:
        logging.error("Invalid token; exiting.")
        return

    while True:
        fn_bytes = recv_prefixed(conn)
        if fn_bytes is None or fn_bytes == b'':
            logging.info("Client signaled quit.")
            break
        fn = fn_bytes.decode()

        file_hash = recv_prefixed(conn).decode()
        iv = base64.b64decode(recv_prefixed(conn))

        logging.info(f"Receiving {fn!r}")

        fragments = {}
        expected_total = None
        ip_id = None

        def on_frag(pkt):
            nonlocal expected_total, ip_id
            if not (IP in pkt and ICMP in pkt):
                return False

            ip = pkt[IP]
            # manual IP checksum check
            raw = bytes(ip)
            ihl = raw[0] & 0x0F
            hdr = raw[:ihl*4]
            hdr_zero = hdr[:10] + b'\x00\x00' + hdr[12:]
            if ip.chksum != scapy_checksum(hdr_zero):
                logging.warning("Bad IP checksum, dropping")
                return False

            if ip_id is None:
                ip_id = ip.id
                logging.info(f"Using IP-ID={ip_id}")
            if ip.id != ip_id:
                return False

            off = ip.frag * 8
            fragments[off] = bytes(pkt[ICMP].payload)

            if ip.flags.MF == 0:
                expected_total = off + len(fragments[off])
                logging.info(f"Last frag at offset {off}, total={expected_total}")

            if expected_total is not None:
                if sum(len(v) for v in fragments.values()) >= expected_total:
                    return True
            return False

        sniff(filter=f"icmp and host {addr[0]}", prn=on_frag,
              stop_filter=lambda pkt: on_frag(pkt) is True, timeout=30)

        if expected_total is None or sum(len(v) for v in fragments.values()) < expected_total:
            logging.error("Incomplete fragments, skipping file.")
            continue

        ciphertext = reassemble(fragments, expected_total)

        try:
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            continue

        outpath = unique_received_path(os.path.basename(fn))
        with open(outpath, 'wb') as f:
            f.write(plaintext)
        logging.info(f"Wrote {outpath}")

        if hashlib.sha256(plaintext).hexdigest() == file_hash:
            logging.info("SHA-256 integrity check PASSED.")
        else:
            logging.error("SHA-256 integrity check FAILED.")

    conn.close()
    ctl.close()
    logging.info("Server shut down.")

if __name__ == '__main__':
    start_server()
