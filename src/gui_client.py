#!/usr/bin/env python3
import threading
import time
import socket
import os
import hashlib
import base64
import random
import logging
import sys

import tkinter as tk
from tkinter import simpledialog, filedialog, ttk, messagebox

from scapy.all import IP, ICMP, fragment

from clientV3 import (
    HOST, PORT, SECRET_KEY, MTU, PACKET_LOSS_PROB, MAX_RETRANSMISSIONS,
    send_prefixed, recv_prefixed, send_fragments
)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

VALID_TOKEN = "C1H4L3"

class FileTransferGUI:
    def __init__(self, master, token):
        self.master = master
        master.title("Dosya Transfer Görselleştirme")
        master.protocol("WM_DELETE_WINDOW", self.on_close)

        self.token = token
        self.filepath = None
        self.transfer_thread = None
        self._stop_flag = threading.Event()

        # UI elemanları
        self.select_btn = tk.Button(master, text="Dosya Seç", command=self.select_file)
        self.select_btn.pack(pady=5)

        self.progress = ttk.Progressbar(master, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=5)

        self.log = tk.Text(master, height=10, width=60, state="disabled")
        self.log.pack(pady=5)

        self.start_btn = tk.Button(master, text="Transferi Başlat", command=self.start_transfer)
        self.start_btn.pack(side="left", padx=10, pady=10)

        self.stop_btn = tk.Button(master, text="Durdur", command=self.stop_transfer, state="disabled")
        self.stop_btn.pack(side="right", padx=10, pady=10)

        # Kalıcı kontrol bağlantısı aç
        self.ctl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ctl.connect((HOST, PORT))
        send_prefixed(self.ctl, self.token.encode())

    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        if self.filepath:
            self.log_message(f"Seçilen dosya: {self.filepath}")

    def start_transfer(self):
        if not self.filepath:
            messagebox.showwarning("Uyarı", "Önce bir dosya seçmelisiniz!")
            return
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._stop_flag.clear()
        self.transfer_thread = threading.Thread(target=self.transfer_process, daemon=True)
        self.transfer_thread.start()

    def stop_transfer(self):
        self._stop_flag.set()
        self.log_message("Transfer durduruluyor...")

    def transfer_process(self):
        try:
            fn = os.path.basename(self.filepath)
            with open(self.filepath, 'rb') as f:
                data = f.read()
            file_hash = hashlib.sha256(data).hexdigest().encode()

            cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
            ct = cipher.encrypt(pad(data, AES.block_size))
            iv_b64 = base64.b64encode(cipher.iv)

            # Metadata gönder
            send_prefixed(self.ctl, fn.encode());       self.log_message(f"Dosya adı gönderildi: {fn}")
            send_prefixed(self.ctl, file_hash);         self.log_message("SHA-256 hash gönderildi")
            send_prefixed(self.ctl, iv_b64);            self.log_message("IV gönderildi")
            time.sleep(0.05)

            # Scapy paketi ve fragment sayısı
            ip_id = random.randint(0, 0xFFFF)
            pkt = IP(dst=HOST, id=ip_id, ttl=64, flags=0)/ICMP()/ct

            max_payload = MTU - 20 - 8
            frag_size  = (max_payload // 8) * 8
            total_frags = len(fragment(pkt, fragsize=frag_size))
            self.log_message(f"Toplam fragment sayısı: {total_frags}")

            # Gönderim döngüsü
            retrans = 0
            while retrans <= MAX_RETRANSMISSIONS and not self._stop_flag.is_set():
                self.log_message(f"Transfer denemesi {retrans+1}/{MAX_RETRANSMISSIONS+1}")
                bytes_sent = send_fragments(ip_id, pkt, PACKET_LOSS_PROB)
                self.log_message(f"{bytes_sent} bayt gönderildi")
                percent = min(100, int((retrans+1)/(MAX_RETRANSMISSIONS+1)*100))
                self.progress['value'] = percent

                resp = recv_prefixed(self.ctl)
                if resp == b'DONE':
                    self.log_message("Transfer başarıyla tamamlandı!")
                    self.progress['value'] = 100
                    break
                elif resp == b'INCOMPLETE':
                    self.log_message("Eksik paket var, yeniden denenecek...")
                    retrans += 1
                    ip_id = random.randint(0, 0xFFFF)
                    time.sleep(1)
                else:
                    self.log_message(f"Beklenmeyen yanıt: {resp}")
                    break

            if self._stop_flag.is_set():
                self.log_message("Transfer yarıda bırakıldı.")
        except Exception as e:
            self.log_message(f"Hata: {e}")
        finally:
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    def log_message(self, msg):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def on_close(self):
        # Transfer varsa durdur
        self._stop_flag.set()
        if self.transfer_thread and self.transfer_thread.is_alive():
            self.transfer_thread.join(timeout=1)
        # Kontrol soketini kapat
        try:
            self.ctl.close()
        except:
            pass
        self.master.destroy()
        sys.exit(0)

def prompt_login(root):
    while True:
        token = simpledialog.askstring("Giriş", "Lütfen erişim token’ınızı girin:", show='*', parent=root)
        if token is None:
            root.destroy()
            return None
        if token == VALID_TOKEN:
            return token
        messagebox.showerror("Hata", "Geçersiz token, tekrar deneyin.", parent=root)

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()

    token = prompt_login(root)
    if token:
        root.deiconify()
        app = FileTransferGUI(root, token)
        root.mainloop()
