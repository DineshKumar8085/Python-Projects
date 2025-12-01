import csv
import os
from datetime import datetime

from scapy.utils import PcapWriter

# Define folder for logs
LOG_DIR = "/home/dinesh/Documents/wifi-packet-sniffer-analyzer/logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Generate timestamped filenames
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
CSV_FILE = os.path.join(LOG_DIR, f"wifi_sniffer_{timestamp}.csv")
PCAP_FILE = os.path.join(LOG_DIR, f"wifi_sniffer_{timestamp}.pcap")

pcap_writer = None


def init_log_files():
    """Initialize CSV and PCAP log files."""
    global pcap_writer

    # Create and write CSV header
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp", "Source MAC", "Destination MAC", "BSSID",
            "SSID", "Security", "Channel", "RSSI", "Type", "Subtype", "Length (bytes)"
        ])

    pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)

    print(f"[+] Logging initialized:")
    print(f"    CSV  → {CSV_FILE}")
    print(f"    PCAP → {PCAP_FILE}")


def log_packet_to_csv(pkt_info: dict):
    """Append parsed packet data to the CSV log."""
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            pkt_info["timestamp"],
            pkt_info["src_mac"],
            pkt_info["dest_mac"],
            pkt_info["bssid"],
            pkt_info["ssid"],
            pkt_info["security"],
            pkt_info["channel"],
            pkt_info["rssi"],
            pkt_info["pkt_type"],
            pkt_info["pkt_subtype"],
            pkt_info["length"]
        ])


def log_raw_packet(pkt):
    """Append the raw Scapy packet into the PCAP file."""
    global pcap_writer

    if pcap_writer:
        try:
            pcap_writer.write(pkt)   # <-- Correct way (handles RadioTap properly)
        except Exception as e:
            print(f"[!] PCAP write error: {e}")
