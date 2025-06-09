from scapy.all import *
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# The IP addresses of the client and server (to simulate MITM)
client_ip = "127.0.0.1"  # Client's IP
server_ip = "127.0.0.1"  # Server's IP
client_port = 12346  # Port number used by the client
server_port = 12346  # Port number used by the server


# Define a function to intercept and log packets
def packet_interceptor(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        # Log packet details
        logging.info(f"Intercepted packet from {ip_src} to {ip_dst}")

        # Log payload (fragment data or any other data in the packet)
        if packet.haslayer(Raw):
            logging.info(f"Packet Data: {packet[Raw].load[:50]}...")  # Log first 50 bytes of the payload

        # Modify packet (e.g., inject data or alter content)
        if ip_src == client_ip:
            # Example: Changing packet content (injecting fake data)
            logging.info("Injecting malicious packet content...")
            packet[Raw].load = b"malicious_data_injected"

        # Forward the packet to the destination
        if ip_dst == server_ip:
            send(packet)
        else:
            send(packet)  # Forward to the next hop or destination


# Sniff packets between the client and server using Layer 3 (IP)
sniff(filter=f"ip and port {client_port} or {server_port}", prn=packet_interceptor, store=0)
