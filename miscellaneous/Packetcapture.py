from scapy.all import *
import time

# Define the packet count threshold
PACKET_THRESHOLD = 30

# Function to capture packets and write them to a pcap file
def capture_packets(packet_count):
    # Capture packets
    packets = sniff(count=packet_count)
    
    # Generate a unique file name for the pcap file based on the current timestamp
    file_name = f"capture_{int(time.time())}.pcap"
    
    # Write packets to a pcap file
    wrpcap(file_name, packets)

    print(f"Captured {packet_count} packets and saved to {file_name}")

# Infinite loop to continuously capture packets
while True:
    # Capture packets and write to a pcap file when the threshold is reached
    capture_packets(PACKET_THRESHOLD)
