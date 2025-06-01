# client.py
import socket
import os
import struct
import hashlib
import logging
import base64
import random
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import IP, ICMP, fragment, send
from scapy.utils import checksum as scapy_checksum

# ——— Configuration ———
HOST = '127.0.0.1'
PORT = 12346
SECRET_KEY = b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef'
MTU = 1500
PACKET_LOSS_PROB = 0.1

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_prefixed(sock, data: bytes):
    """Send a 2-byte big-endian length, then the data."""
    sock.send(struct.pack('!H', len(data)))
    sock.sendall(data)

def compute_ip_checksum(pkt):
    raw = bytes(pkt)
    ihl = raw[0] & 0x0F
    hdr = raw[:ihl*4]
    hdr_zero = hdr[:10] + b'\x00\x00' + hdr[12:]
    pkt.chksum = scapy_checksum(hdr_zero)

def send_fragments(ip_id, pkt):
    max_payload = MTU - 20 - 8
    frag_size = (max_payload // 8) * 8
    frags = fragment(pkt, fragsize=frag_size)
    logging.info(f"Fragmented into {len(frags)} pieces (IP ID={ip_id})")
    for f in frags:
        compute_ip_checksum(f)
        if random.random() < PACKET_LOSS_PROB:
            logging.warning(f"[DROP] offset={f.frag*8}")
            continue
        send(f, verbose=False)
        logging.info(
            f"Sent frag offset={f.frag*8}, MF={int(f.flags.MF)}, checksum=0x{f.chksum:04x}"
        )

def main():
    ctl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctl.connect((HOST, PORT))

    token = input("Token: ")
    send_prefixed(ctl, token.encode())

    while True:
        fn = input("File to send (or 'q'): ")
        if fn.lower() in ('q','quit'):
            send_prefixed(ctl, b'')  # zero-length signals quit
            break
        if not os.path.isfile(fn):
            print("❌ No such file")
            continue

        with open(fn, 'rb') as f:
            data = f.read()
        file_hash = hashlib.sha256(data).hexdigest().encode()
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        ct = cipher.encrypt(pad(data, AES.block_size))
        iv_b64 = base64.b64encode(cipher.iv)

        # send metadata
        send_prefixed(ctl, os.path.basename(fn).encode())
        send_prefixed(ctl, file_hash)
        send_prefixed(ctl, iv_b64)
        time.sleep(0.05)

        # build and fragment
        ip_id = random.randint(0, 0xFFFF)
        pkt = IP(dst=HOST, id=ip_id, ttl=64, flags=0) / ICMP(type=8) / ct
        send_fragments(ip_id, pkt)

        logging.info("Done sending all fragments.\n")

    ctl.close()

if __name__ == '__main__':
    main()
