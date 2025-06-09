#!/usr/bin/env python3
import threading
import socket
import struct
import os
import random
import hashlib
import base64
import logging
import tkinter as tk
from tkinter import ttk, messagebox
import warnings

from scapy.all import sniff, IP, ICMP
from scapy.utils import checksum as scapy_checksum
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ——— Configuration (match serverV3.py) ———
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

class ServerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Server GUI - File Receiver")
        master.protocol("WM_DELETE_WINDOW", self.on_close)

        # UI: Start/Stop buttons
        frame = tk.Frame(master)
        frame.pack(padx=10, pady=5, fill="x")

        self.start_btn = tk.Button(frame, text="Start Server", command=self.start_server)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = tk.Button(frame, text="Stop Server", command=self.stop_server, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        # UI: Log display
        self.log = tk.Text(master, height=15, width=80, state="disabled")
        self.log.pack(padx=10, pady=(0,5), fill="both", expand=True)

        # UI: Received files list
        tk.Label(master, text="Received Files:").pack(anchor="w", padx=10)
        self.file_list = tk.Listbox(master, height=5)
        self.file_list.pack(padx=10, pady=(0,10), fill="x")

        # Server control
        self.server_thread = None
        self.stop_flag = threading.Event()
        self.sock = None

    def log_message(self, msg):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def add_file(self, filepath):
        self.file_list.insert("end", filepath)

    def start_server(self):
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.stop_flag.clear()
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()
        self.log_message(f"[+] Server starting on {HOST}:{PORT}…")

    def stop_server(self):
        self.stop_flag.set()
        try:
            if self.sock:
                self.sock.close()  # interrupt accept()
        except:
            pass
        self.log_message("[*] Server stopping…")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def run_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((HOST, PORT))
            self.sock.listen(1)
        except Exception as e:
            self.log_message(f"❌ Failed to bind: {e}")
            return

        while not self.stop_flag.is_set():
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break  # socket closed
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

        if self.sock:
            self.sock.close()
        self.log_message("[*] Server stopped.")

    def handle_client(self, conn, addr):
        self.log_message(f"[+] Connection from {addr}")
        try:
            # 1) Validate token
            token = recv_prefixed(conn).decode()
            if token != VALID_TOKEN:
                self.log_message(f"[-] Invalid token from {addr}, closing.")
                conn.close()
                return
            self.log_message("[*] Token validated.")

            while not self.stop_flag.is_set():
                # 2) Filename
                try:
                    fn_bytes = recv_prefixed(conn)
                except ConnectionError:
                    self.log_message(f"[*] {addr} closed connection.")
                    break
                if fn_bytes == b'':  # client signaled quit
                    self.log_message(f"[ ] {addr} signaled quit.")
                    break
                fn = fn_bytes.decode()
                self.log_message(f"[*] Receiving: {fn}")

                # 3) Hash & IV
                file_hash = recv_prefixed(conn).decode()
                iv = base64.b64decode(recv_prefixed(conn))

                # 4) Capture fragments
                fragments = {}
                expected_total = None
                current_id = None

                def on_frag(pkt):
                    nonlocal expected_total, current_id
                    if IP not in pkt or ICMP not in pkt:
                        return False
                    ip = pkt[IP]
                    # checksum verify
                    raw = bytes(ip); ihl=(raw[0]&0x0F)*4
                    hdr = raw[:ihl]; hdr_zero = hdr[:10]+b'\x00\x00'+hdr[12:]
                    if ip.chksum != scapy_checksum(hdr_zero):
                        self.log_message(f"[DROP] bad checksum 0x{ip.chksum:04x}")
                        return False
                    if current_id is None:
                        current_id = ip.id
                    elif ip.id != current_id:
                        return False
                    off = ip.frag * 8
                    fragments[off] = bytes(pkt[ICMP].payload)
                    if ip.flags.MF == 0:
                        expected_total = off + len(fragments[off])
                        self.log_message(f"    last frag offset={off}, total={expected_total}")
                    # stop if all bytes arrived
                    if expected_total and sum(len(v) for v in fragments.values()) >= expected_total:
                        return True
                    return False

                sniff(prn=on_frag,
                      stop_filter=lambda p: on_frag(p) is True,
                      timeout=10)

                # 5) Check completeness
                if expected_total is None or sum(len(v) for v in fragments.values()) < expected_total:
                    self.log_message("[-] Incomplete – ask client to retransmit.")
                    send_prefixed(conn, b'INCOMPLETE')
                    continue

                # 6) Reassemble & decrypt
                buf = bytearray(expected_total)
                for off, chunk in fragments.items():
                    buf[off:off+len(chunk)] = chunk
                ciphertext = bytes(buf)

                try:
                    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
                    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                except Exception as e:
                    self.log_message(f"[-] Decrypt error: {e}")
                    send_prefixed(conn, b'ERROR')
                    continue

                # 7) Write file & integrity check
                outpath = unique_received_path(fn)
                with open(outpath, 'wb') as f:
                    f.write(plaintext)
                self.log_message(f"[+] Saved: {outpath}")
                self.add_file(outpath)

                if hashlib.sha256(plaintext).hexdigest() == file_hash:
                    self.log_message("[✔] SHA-256 OK.")
                    send_prefixed(conn, b'DONE')
                else:
                    self.log_message("[!] SHA-256 MISMATCH.")
                    send_prefixed(conn, b'FAILED_HASH')

        except Exception as e:
            self.log_message(f"❌ Error with {addr}: {e}")
        finally:
            conn.close()
            self.log_message(f"[*] Connection {addr} closed.")

    def on_close(self):
        if messagebox.askokcancel("Quit", "Stop server and quit?"):
            self.stop_server()
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
