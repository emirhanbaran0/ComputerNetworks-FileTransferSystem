import socket
import os
import math
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import logging
import time
import random
from scapy.all import IP, ICMP, send


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

host = '127.0.0.1'
port = 12346
secret_key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef'

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))

token = input("Enter authentication token: ")
client_socket.send(token.encode())

filename = input("Enter the file path to send: ")
if not os.path.isfile(filename):
    logging.error("File does not exist.")
    exit()

sha256_hash = hashlib.sha256()
with open(filename, 'rb') as f:
    while chunk := f.read(1024):
        sha256_hash.update(chunk)

file_hash = sha256_hash.hexdigest()
logging.info(f"Calculated file hash: {file_hash}")

client_socket.send(filename.encode())
client_socket.send(file_hash.encode())


start_time = time.time()

with open(filename, 'rb') as f:
    file_data = f.read()
    total_fragments = math.ceil(len(file_data) / 1024)

    logging.info(f"Sending file: {filename} in {total_fragments} fragments.")

    cipher = AES.new(secret_key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

    client_socket.send(base64.b64encode(cipher.iv))
    client_socket.send(encrypted_data)

    packet_loss_probability = 0.1

    for i in range(total_fragments):
        if random.random() < packet_loss_probability:
            logging.warning(f"Simulating packet loss for fragment {i + 1}")
            continue

        fragment = encrypted_data[i * 1024:(i + 1) * 1024]
        seq_num = i
        logging.info(f"Sending fragment {seq_num + 1} of {total_fragments}")

        ip_packet = IP(dst=host, ttl=64, id=12345, flags="DF", proto=1)
        icmp_packet = ICMP(type=8, id=seq_num) / fragment

        logging.info(f"Packet {seq_num + 1} details:")
        logging.info(f"  IP Header: {ip_packet.summary()}")
        logging.info(f"  ICMP Header: {icmp_packet.summary()}")
        logging.info(f"  Fragment: {fragment[:50]}...")
        send(ip_packet / icmp_packet)

end_time = time.time()

latency = end_time - start_time
logging.info(f"File sent in {latency} seconds (Round-trip time / Latency)")

bytes_sent = len(file_data)
bandwidth = bytes_sent / latency
logging.info(f"Bandwidth: {bandwidth} bytes per second")

client_socket.close()
