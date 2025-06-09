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
MAX_RETRANSMISSIONS = 3 # Maximum number of retransmissions

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_prefixed(sock, data: bytes):
    """Send a 2-byte big-endian length, then the data."""
    sock.sendall(struct.pack('!H', len(data)))
    if data:
        sock.sendall(data)

def recv_prefixed(sock) -> bytes:
    """Receive a 2-byte length then that many bytes (or b'' if length==0)."""
    hdr = sock.recv(2)
    if not hdr:
        raise ConnectionError("Connection closed")
    length, = struct.unpack('!H', hdr)
    if length == 0:
        return b''
    buf = b''
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed mid-message")
        buf += chunk
    return buf

def compute_ip_checksum(pkt):
    """Serialize pkt, zero its IP checksum field, recompute, and set pkt.chksum."""
    raw = bytes(pkt)
    ihl = raw[0] & 0x0F
    hdr = raw[:ihl*4]
    hdr_zero = hdr[:10] + b'\x00\x00' + hdr[12:]
    pkt.chksum = scapy_checksum(hdr_zero)

def send_fragments(ip_id, pkt, packet_loss_prob): # Modified: accept packet_loss_prob
    """
    Fragment the packet, compute manual checksums, send each fragment,
    and return total bytes sent.
    """
    max_payload = MTU - 20 - 8
    frag_size = (max_payload // 8) * 8
    frags = fragment(pkt, fragsize=frag_size)
    logging.info(f"Fragmented into {len(frags)} pieces (IP ID={ip_id})")

    bytes_sent = 0
    for f in frags:
        compute_ip_checksum(f)
        raw = bytes(f)
        if random.random() < packet_loss_prob: # Use dynamic packet_loss_prob
            logging.warning(f"[DROP] offset={f.frag*8}")
            continue
        send(f, verbose=False)
        bytes_sent += len(raw)
        logging.info(
            f"Sent frag offset={f.frag*8}, "
            f"MF={int(f.flags.MF)}, checksum=0x{f.chksum:04x}, "
            f"{len(raw)} bytes"
        )
    return bytes_sent

def main():
    ctl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctl.connect((HOST, PORT))

    token = input("Token: ")
    send_prefixed(ctl, token.encode())

    while True:
        fn = input("File to send (or 'q'): ")
        if fn.lower() in ('q','quit'):
            send_prefixed(ctl, b'')  # zero-length → quit
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

        # Build packet once, re-use for retransmissions
        ip_id = random.randint(0, 0xFFFF)
        pkt_to_send = IP(dst=HOST, id=ip_id, ttl=64, flags=0)/ICMP(type=8)/ct

        retransmissions = 0
        file_sent_successfully = False

        while retransmissions <= MAX_RETRANSMISSIONS:
            logging.info(f"Attempting to send file (Retransmission {retransmissions}/{MAX_RETRANSMISSIONS})")

            # measure send bandwidth
            t_send_start = time.time()
            bytes_sent = send_fragments(ip_id, pkt_to_send, PACKET_LOSS_PROB) # Pass packet_loss_prob
            t_send_end = time.time()
            send_duration = t_send_end - t_send_start
            if send_duration > 0:
                mbps = (bytes_sent * 8) / (send_duration * 1e6)
                logging.info(f"Sent {bytes_sent} B in {send_duration:.3f} s → {mbps:.2f} Mbps")
            else:
                logging.warning("Send duration too small to measure bandwidth")

            # measure RTT
            t0 = t_send_start
            try:
                resp = recv_prefixed(ctl)
                if resp == b'DONE':
                    rtt_ms = (time.time() - t0)*1000
                    logging.info(f"Round-trip time: {rtt_ms:.1f} ms")
                    logging.info("File transfer successful.")
                    file_sent_successfully = True
                    break # Exit retransmission loop
                elif resp == b'INCOMPLETE':
                    logging.warning(f"Server reported incomplete fragments. Retransmitting... (Attempt {retransmissions+1})")
                    retransmissions += 1
                    # Increment IP ID for retransmission to ensure server treats it as a new attempt
                    ip_id = random.randint(0, 0xFFFF)
                    pkt_to_send = IP(dst=HOST, id=ip_id, ttl=64, flags=0)/ICMP(type=8)/ct
                    time.sleep(1) # Give server time to process and for network to clear
                else:
                    logging.warning(f"Unexpected control message: {resp!r}")
                    break # Exit loop on unexpected message
            except ConnectionError as e:
                logging.error(f"Control connection error: {e}. Aborting retransmissions.")
                break # Exit loop on connection error

        if not file_sent_successfully:
            logging.error(f"File transfer failed after {MAX_RETRANSMISSIONS} retransmissions.")

    ctl.close()

if __name__ == '__main__':
    main()