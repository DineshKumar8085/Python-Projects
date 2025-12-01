def map_of_packets(pkt_type, pkt_subtype):
    type_names = {0:"Management", 1:"Control", 2:"Data", 3:"Extension"}
    subtype_names = {
        0: {  # Management frames
            0: "Association Request", 1: "Association Response", 2: "Reassociation Request",
            3: "Reassociation Response", 4: "Probe Request", 5: "Probe Response", 6: "Timing Advertisement",
            7: "Reserved", 8: "Beacon", 9: "ATIM", 10: "Disassociation", 11: "Authentication", 12: "Deauthentication",
            13: "Action", 14: "Action No ACK (NACK)", 15: "Reserved"
        },
        1: {  # Control frames
            0: "Reserved", 1: "Reserved", 2: "Trigger", 3: "TACK", 4: "Beamforming Report Poll",
            5: "VHT/HE NDP Announcement", 6: "Control Frame Extension", 7: "Control Wrapper",
            8: "Block Ack Request (BAR)", 9: "Block Ack (BA)", 10: "PS-Poll",
            11: "RTS", 12: "CTS", 13: "ACK", 14: "CF-End", 15: "CF-End + ACK"
        },
        2: {  # Data frames
            0: "Data", 1: "Reserved", 2: "Reserved", 3: "Reserved",  4: "NULL (No data)", 5: "Reserved", 6: "Reserved",
            7: "Reserved", 8: "QoS Data", 9: "QoS Data + CF-ACK", 10: "QoS Data + CF-Poll",
            11: "QoS Data + CF-ACK + CF-Poll", 12: "QoS NULL (No data)", 13: "Reserved", 14: "QoS CF-Poll (no data)",
            15: "QoS CF-ACK + CF-Poll (no data)"
        },
        3: {  # Extension frames
            0: "DMG Beacon", 1: "S1G Beacon"
        }
    }

    pkt_type_name = type_names.get(pkt_type, "Unknown Type")
    pkt_subtype_name = subtype_names.get(pkt_type, {}).get(pkt_subtype, "Unknown Subtype")

    print(f"Packet Type: {pkt_type_name}")
    print(f"Packet Subtype: {pkt_subtype_name}")