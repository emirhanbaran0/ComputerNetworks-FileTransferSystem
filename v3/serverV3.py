# server.py
import socket
import os
import struct
import hashlib
import logging
import base64
import random
import time # Added for timeout in sniff

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

def send_prefixed(sock, data: bytes):
    sock.sendall(struct.pack('!H', len(data)))
    if data:
        sock.sendall(data)

def recv_prefixed(sock) -> bytes:
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
        # Ensure chunk fits within the allocated buffer
        if off + len(chunk) > total_len:
            logging.warning(f"Fragment extends beyond expected total length. Offset: {off}, Chunk Len: {len(chunk)}, Total Len: {total_len}")
            # Optionally handle this as an error or clip the chunk
            # For now, we'll try to put it in, but it might cause issues if total_len is strictly enforced.
            # A more robust solution would re-evaluate total_len or discard the packet.
            pass
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
        conn.close()
        ctl.close()
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
        current_ip_id = None # Renamed from ip_id to current_ip_id to avoid confusion with new sniff parameter

        def on_frag(pkt):
            nonlocal expected_total, current_ip_id, fragments
            if not (IP in pkt and ICMP in pkt):
                return False

            ip = pkt[IP]
            # Manual IP checksum verification
            raw = bytes(ip)
            ihl = raw[0] & 0x0F
            hdr = raw[:ihl*4]
            hdr_zero = hdr[:10] + b'\x00\x00' + hdr[12:]
            if ip.chksum != scapy_checksum(hdr_zero):
                logging.warning(f"Bad IP checksum 0x{ip.chksum:04x} (expected 0x{scapy_checksum(hdr_zero):04x}), dropping")
                return False

            # If this is a new IP ID, reset state (implies retransmission of entire file)
            if current_ip_id is None:
                current_ip_id = ip.id
                logging.info(f"Setting expected IP-ID={current_ip_id}")
            elif ip.id != current_ip_id:
                logging.info(f"Ignoring packet with different IP-ID ({ip.id}) than current ({current_ip_id}). Likely a retransmission attempt.")
                return False # Ignore packets from previous or different attempts

            off = ip.frag * 8
            fragments[off] = bytes(pkt[ICMP].payload)

            if ip.flags.MF == 0:
                # This is the last fragment, so we now know the expected total length
                new_expected_total = off + len(fragments[off])
                if expected_total is None or new_expected_total > expected_total:
                    expected_total = new_expected_total
                    logging.info(f"Last frag at offset {off}, total={expected_total}")

            # Condition to stop sniffing:
            # We need to know the expected_total, and all fragments up to that total must be received.
            if expected_total is not None:
                current_received_length = sum(len(v) for v in fragments.values())
                # Check if all expected fragments are present and their combined length matches expected_total
                if current_received_length >= expected_total:
                    # Quick check for contiguous fragments to ensure all parts are there
                    # This is a basic check. A more robust one would iterate through sorted keys
                    # and ensure no gaps. For simplicity, we just check total length.
                    logging.info(f"Received total length {current_received_length}, Expected {expected_total}. Attempting reassembly.")
                    return True # Stop sniffing
            return False # Continue sniffing

        # Sniff with a timeout to prevent indefinite waiting for fragments
        # The timeout duration might need adjustment based on network conditions
        sniff_result = sniff(
            filter=f"icmp and host {addr[0]}",
            prn=on_frag,
            stop_filter=lambda pkt: on_frag(pkt) is True,
            timeout=10 # Reduced timeout to quickly detect incomplete transfers for retransmission
        )

        # Check if sniff stopped due to timeout or successful reassembly
        is_complete = False
        if expected_total is not None and sum(len(v) for v in fragments.values()) >= expected_total:
            is_complete = True
            # Also, check if the actual reassembled data size matches expected_total
            # (though reassemble function handles this by pre-allocating buffer)
            # A more robust check might be to ensure all offsets from 0 up to expected_total are covered.

        if not is_complete:
            logging.error("Incomplete fragments received (or timed out). Signalling client to retransmit.")
            send_prefixed(conn, b'INCOMPLETE') # Signal client to retransmit
            continue # Go back to waiting for next file/retransmission

        ciphertext = reassemble(fragments, expected_total)

        try:
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            send_prefixed(conn, b'ERROR') # Signal an error to the client
            continue

        outpath = unique_received_path(os.path.basename(fn))
        with open(outpath, 'wb') as f:
            f.write(plaintext)
        logging.info(f"Wrote {outpath}")

        if hashlib.sha256(plaintext).hexdigest() == file_hash:
            logging.info("SHA-256 check PASSED.")
            send_prefixed(conn, b'DONE') # Signal client that reassembly + integrity check is done
        else:
            logging.error("SHA-256 check FAILED.")
            send_prefixed(conn, b'FAILED_HASH') # Signal hash mismatch to client

    conn.close()
    ctl.close()
    logging.info("Server shut down.")

if __name__ == '__main__':
    start_server()