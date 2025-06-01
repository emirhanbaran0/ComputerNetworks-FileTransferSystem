import socket
import os
import hashlib
import logging
import base64
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Server Configuration
HOST = '0.0.0.0'       # Accept connections from any IP
PORT = 12346           # Port number
SECRET_KEY = b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef'  # 16-byte AES key
VALID_TOKEN = "C1H4L3"  # Expected auth token

def unique_received_path(safe_name, prefix="received_", max_tries=1000):
    """
    Generate a path like "received_{safe_name}" and, if it exists,
    insert a random number after the prefix, e.g. "received_834_{safe_name}",
    until it doesn't exist.
    """
    # initial candidate without suffix
    candidate = f"{prefix}{safe_name}"
    tries = 0

    # while it exists, insert random suffix after prefix
    while os.path.exists(candidate) and tries < max_tries:
        suffix = random.randint(0, 9999)
        candidate = f"{prefix}{suffix}_{safe_name}"
        tries += 1

    if os.path.exists(candidate):
        raise FileExistsError(f"Could not find a free filename after {max_tries} attempts")
    return candidate

def start_server():
    # Set up the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    logging.info(f"Server listening on {HOST}:{PORT}...")

    try:
        client_socket, addr = server_socket.accept()
        logging.info(f"Connection from {addr}")
    except Exception as e:
        logging.error(f"Error accepting connection: {e}")
        server_socket.close()
        return

    # 1) Authenticate once
    token = client_socket.recv(1024).decode()
    if token != VALID_TOKEN:
        logging.error("Invalid authentication token.")
        client_socket.close()
        server_socket.close()
        return

    # 2) Loop until client says 'q' or 'quit'
    while True:
        # Receive the filename (or quit sentinel)
        filename = client_socket.recv(1024).decode()
        if not filename:
            logging.info("Client closed connection.")
            break
        if filename.lower() in ('q', 'quit'):
            logging.info("Client requested to quit.")
            break

        # Receive the expected SHA-256 hash
        file_hash = client_socket.recv(64).decode()
        logging.info(f"Received file hash: {file_hash}")

        # Receive the IV and encrypted data
        try:
            iv_b64 = client_socket.recv(24)
            iv = base64.b64decode(iv_b64)
            encrypted_data = client_socket.recv(10_000_000)  # adjust buffer as needed
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
            break

        # Decrypt
        try:
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            break

        # Save file with unique name
        safe_name = os.path.basename(filename)
        try:
            out_path = unique_received_path(safe_name)
            with open(out_path, 'wb') as f:
                f.write(decrypted_data)
            logging.info(f"File saved as {out_path}")
        except Exception as e:
            logging.error(f"Error saving file: {e}")
            continue

        # Verify integrity
        sha256 = hashlib.sha256()
        sha256.update(decrypted_data)
        calc_hash = sha256.hexdigest()
        logging.info(f"Calculated hash: {calc_hash}")
        if calc_hash == file_hash:
            logging.info("File integrity verified successfully!")
        else:
            logging.error("File integrity verification FAILED!")

    # Clean up
    client_socket.close()
    server_socket.close()
    logging.info("Server shut down.")

if __name__ == '__main__':
    start_server()
