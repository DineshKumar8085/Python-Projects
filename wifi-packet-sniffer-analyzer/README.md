# WiFi Packet Sniffer & Analyzer

A real-time WiFi packet capturing and analysis tool built using Python, Scapy, and Monitor Mode interfaces, capable of classifying WiFi frames, extracting key information fields, generating analytics, and storing captured packets in **CSV** and **PCAP** formats for offline analysis.

## Project Overview

This project implements a complete 802.11 WiFi packet sniffing and analysis system.

It captures packets directly from a wireless network interface configured in *monitor mode* and processes them to extract meaningful information about surrounding WiFi activity.

The analyzer features:

- Live packet capture from WLAN monitor interface
- Frame classification (Management, Control, Data)
- Subtype identification (Beacon, Probe, QoS, Null Data, etc.)
- Extraction of essential 802.11 fields
- Dynamic counters and aggregators
- Structured storage
    - CSV logging (parsed data)
    - PCAP logging (raw packets)
- Modular architecture for readability and maintainability

This repository is designed to help beginners and intermediate developers understand Scapy-based WiFi sniffing while providing a well-organized, production-ready structure.

## Purpose of This Project

This tool is useful for:

- Wireless network analysis
- Security research & WiFi auditing
- Classroom/lab activities for networking courses
- Understanding 802.11 frame structures
- Collecting datasets for ML-based WiFi intrusion/classification projects
- Custom packet logging for research

## Technologies Used

| Component | Technology |
| --- | --- |
| Programming Language | Python 3 |
| Packet Sniffing | Scapy |
| Logging | CSV, PCAP |
| Analysis | Custom classifiers & counters |
| OS | Linux (Monitor mode supported) |

## Getting Started

### 1) Clone the Repository
git clone git@github.com:DineshKumar8085/Python-Projects.git

### 2) Create a Virtual Environment

python3 -m venv .venv
source .venv/bin/activate

### 3) Install Dependencies

pip install -r requirements.txt

### 4) Enable Monitor Mode on Your WiFi Interface

- sudo airmon-ng check kill
- sudo airmon-ng start wlp2s0

**Note: check for your network interface name and replace it with wlp2s0**

**To check for Network Interface name: Type iwconfig command in the terminal, you can see network interface names like wlan0 or wlp2s0 etc**

### 5) Run the Sniffer

**Use the venv’s Python with sudo:**

sudo .venv/bin/python -m src.main

You’ll see live packet logs and output like:

PACKET_TYPE: 0 | PACKET_SUBTYPE: 8
Packet Type: Management
Packet Subtype: Beacon
2025-11-12 16:21:55 - SSID: MyWiFi | RSSI: -61 | CH: 11

## **Logging Details**

### CSV Logging

**Each packet’s parsed fields are appended into:**

logs/wifi_sniffer_<timestamp>.csv

**Fields include:**

- Timestamp
- Source MAC
- Destination MAC
- BSSID
- SSID
- Security type
- Channel
- RSSI
- Packet type / subtype
- Length (bytes)

### PCAP Logging

**All raw 802.11 frames are stored in:**

logs/wifi_sniffer_<timestamp>.pcap

**Compatible with:**

- Wireshark
- Aircrack-ng tools
- Scapy offline parsing

## Requirements

- Linux or Windows system
- WiFi adapter supporting Monitor Mode + Packet Injection
- Python 3.8+
- Scapy (latest version recommended)
- Root privileges for capture

**Note: All the above mentioned commands uses for Linux System.**
