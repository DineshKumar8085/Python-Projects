from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from src.packet_classifier import map_of_packets
from src.field_extractor import field_extractor
from src.counters_aggregators import PacketStats
from src.storage_logger import init_log_files, log_packet_to_csv, log_raw_packet

stats = PacketStats()

def packet_capture(pkt):
    pkt_type = None
    pkt_subtype = None
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)
        pkt_type = dot11.type
        pkt_subtype = dot11.subtype

    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    map_of_packets(pkt_type, pkt_subtype)
    src_mac, ssid, pkt_info, rssi, length = field_extractor(pkt)
    stats.update(pkt_type, src_mac, ssid, pkt_subtype, rssi, length)
    log_packet_to_csv(pkt_info)
    log_raw_packet(pkt)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

def packet_scanner():
    init_log_files()
    sniff(prn=packet_capture, iface="wlp2s0mon", count=10, store=False)
