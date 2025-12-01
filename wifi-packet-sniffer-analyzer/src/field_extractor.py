from datetime import datetime
from scapy.layers.dot11 import Dot11Elt, RadioTap, Dot11Beacon

def field_extractor(pkt):
    timestamp = datetime.fromtimestamp(pkt.time)
    src_mac_addr = pkt.addr2
    dest_mac_addr = pkt.addr1
    pkt_type = pkt.type
    pkt_subtype = pkt.subtype
    bssid = pkt.addr3
    length = len(pkt)

    # Extract SSID and Security
    ssid, security = None, "open"
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0:
                ssid = elt.info.decode(errors='ignore')
            elif elt.ID == 48:
                security = "WPA2/WPA3"
            elif elt.ID == 221 and elt.info.startswith(b'\x00\x50\xf2\x01'):
                security = "WPA"
            elt = elt.payload.getlayer(Dot11Elt)

    if pkt.haslayer(Dot11Beacon) and pkt[Dot11Beacon].cap.privacy:
        if security == "Open":
            security = "WEP"

    # Extract channel
    channel = None
    for elt in pkt.iterpayloads():
        if elt.haslayer(Dot11Elt) and elt.ID == 3:
            channel = elt.info[0]
            break

    # Extract RSSI
    rssi = pkt.dBm_AntSignal if pkt.haslayer(RadioTap) else None

    pkt_info = {
        "timestamp": timestamp,
        "src_mac": src_mac_addr,
        "dest_mac": dest_mac_addr,
        "bssid": bssid,
        "ssid": ssid if ssid else "None",
        "security": security,
        "channel": channel,
        "rssi": rssi,
        "pkt_type": pkt_type,
        "pkt_subtype": pkt_subtype,
        "length": length
    }

    print(f"[{timestamp}]: {src_mac_addr} -> {dest_mac_addr} | "
          f"BSSID: {bssid} | SSID: {ssid if ssid else 'None'} | "
          f"SECURITY: {security} | CHANNEL: {channel} | RSSI: {rssi} | "
          f"TOTAL_PACKET_SIZE = {length} BYTES")

    return src_mac_addr, ssid, pkt_info, rssi, length
