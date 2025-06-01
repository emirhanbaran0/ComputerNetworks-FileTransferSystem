import socket
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


host = '0.0.0.0'
port = 12346
secret_key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef'
valid_token = "C1H4L3"

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(5)
logging.info(f"Server listening on {host}:{port}...")

try:
    client_socket, addr = server_socket.accept()
    logging.info(f"Connection from {addr}")
except Exception as e:
    logging.error(f"Error accepting connection: {e}")
    server_socket.close()
    exit()

token = client_socket.recv(1024).decode()
if token != valid_token:
    logging.error("Invalid authentication token.")
    client_socket.close()
    exit()

filename = client_socket.recv(1024).decode()

file_hash = client_socket.recv(64).decode()
logging.info(f"Received file hash: {file_hash}")

filename = os.path.basename(filename)

try:
    iv = base64.b64decode(client_socket.recv(24))
    encrypted_data = client_socket.recv(2048)
except Exception as e:
    logging.error(f"Error receiving data from client: {e}")
    client_socket.close()
    exit()


try:
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
except Exception as e:
    logging.error(f"Decryption failed: {e}")
    client_socket.close()
    exit()

try:
    with open(f"received_{filename}", 'wb') as f:
        f.write(decrypted_data)
    logging.info(f"File {filename} reassembled and saved successfully.")
except Exception as e:
    logging.error(f"Error saving file: {e}")

sha256_hash = hashlib.sha256()
sha256_hash.update(decrypted_data)
received_file_hash = sha256_hash.hexdigest()
logging.info(f"Calculated received file hash: {received_file_hash}")

if received_file_hash == file_hash:
    logging.info("File integrity verified successfully!")
else:
    logging.error("File integrity verification failed!")

client_socket.close()
server_socket.close()
