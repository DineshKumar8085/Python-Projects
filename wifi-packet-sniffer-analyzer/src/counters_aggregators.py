from collections import defaultdict, deque
import time

class PacketStats:
    def __init__(self, recent_len=50):
        self.start_time = time.time()
        self.total_packets = 0
        self.type_counts = defaultdict(int)
        self.subtype_counts = defaultdict(int)
        self.mac_counts = defaultdict(int)
        self.ssid_counts = defaultdict(int)
        # keep latest parsed packet summaries for dashboard
        self.recent_packets = deque(maxlen=recent_len)
        # for packet rate
        self.timestamps = deque(maxlen=500)

    def update(self, pkt_type, src_mac, ssid, subtype, rssi, length):
        """Call this for each packet (lightweight)."""
        self.total_packets += 1
        self.timestamps.append(time.time())

        if pkt_type is not None:
            if pkt_type == 0:
                self.type_counts["Management"] += 1
            elif pkt_type == 1:
                self.type_counts["Control"] += 1
            elif pkt_type == 2:
                self.type_counts["Data"] += 1
            else:
                self.type_counts["Other"] += 1

        if subtype:
            self.subtype_counts[subtype] += 1
        if src_mac:
            self.mac_counts[src_mac] += 1
        if ssid:
            self.ssid_counts[ssid] += 1

        # store a small summary to recent_packets for dashboard display
        summary = {
            "ts": time.time(),
            "src": src_mac,
            "ssid": ssid,
            "type": ("Management" if pkt_type==0 else "Control" if pkt_type==1 else "Data" if pkt_type==2 else "Other"),
            "subtype": subtype,
            "rssi": rssi,
            "len": length
        }
        self.recent_packets.appendleft(summary)

    def pkt_rate(self, window_seconds=1.0):
        """Return packets/sec measured over last window_seconds."""
        now = time.time()
        # purge older than window
        while self.timestamps and now - self.timestamps[0] > window_seconds:
            self.timestamps.popleft()
        return len(self.timestamps) / (window_seconds or 1.0)

    def top_macs(self, n=10):
        return sorted(self.mac_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def top_ssids(self, n=10):
        return sorted(self.ssid_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def type_counts_snapshot(self):
        return dict(self.type_counts)

    def subtype_counts_snapshot(self, n=20):
        return sorted(self.subtype_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def recent(self, n=10):
        return list(self.recent_packets)[:n]
