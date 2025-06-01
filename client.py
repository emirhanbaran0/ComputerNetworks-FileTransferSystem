# client.py

import socket
import os
import math
import hashlib
import logging
import base64
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import IP, ICMP, send

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Client Configuration
HOST = '127.0.0.1'    # Server IP (change as needed)
PORT = 12346          # Port number
SECRET_KEY = b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef'  # 16-byte AES key
PACKET_LOSS_PROB = 0.1  # Simulated loss rate

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# 1) Send authentication token
token = input("Enter authentication token: ")
client_socket.send(token.encode())
# (Could check server response here for real-world use)

# 2) Loop until user quits
while True:
    filename = input("Enter file path to send (or 'q' to quit): ")
    if filename.lower() in ('q', 'quit'):
        # Tell server we’re done
        client_socket.send(filename.encode())
        print("Closing connection.")
        break

    if not os.path.isfile(filename):
        logging.error("File does not exist.")
        continue

    # Compute SHA-256 hash
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        while chunk := f.read(1024):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()
    logging.info(f"Calculated file hash: {file_hash}")

    # Send filename and hash
    client_socket.send(filename.encode())
    client_socket.send(file_hash.encode())

    # Read full file and encrypt
    with open(filename, 'rb') as f:
        data = f.read()
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(data, AES.block_size))

    # Send IV and encrypted blob over the TCP socket
    client_socket.send(base64.b64encode(cipher.iv))
    client_socket.send(encrypted)

    # Now send fragments over ICMP, simulating loss
    total_frags = math.ceil(len(encrypted) / 1024)
    logging.info(f"Sending {total_frags} fragments via ICMP (loss rate {PACKET_LOSS_PROB*100:.0f}%)")

    for i in range(total_frags):
        if random.random() < PACKET_LOSS_PROB:
            logging.warning(f"Simulated loss of fragment {i+1}")
            continue
        frag = encrypted[i*1024:(i+1)*1024]
        ip_pkt = IP(dst=HOST, ttl=64, id=12345, flags="DF", proto=1)
        icmp_pkt = ICMP(type=8, id=i) / frag
        send(ip_pkt/icmp_pkt, verbose=False)
        logging.info(f"Sent fragment {i+1}/{total_frags}")

    # Optional: measure RTT / bandwidth
    # (You could wrap the send calls with timestamps if you like.)

# Clean up
client_socket.close()
logging.info("Client shut down.")
