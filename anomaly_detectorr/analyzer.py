from scapy.all import IP, DNS, TCP, UDP
from reputation import check_ip_reputation
from dns_checker import check_dns
from traffic_tracker import check_data_spike

#  trafic database spkie tracking
traffic_db = {}

def analyze_packet(pkt, config, local_ip):
    if not pkt.haslayer(IP):
        return []

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    reasons = []

    
    direction = "outbound" if src_ip == local_ip else "inbound"

    
    if direction == "outbound":
        rep_reason = check_ip_reputation(dst_ip, config)
        if rep_reason:
            reasons.append(f"Reputation alert: {rep_reason}")

    # DNS check
    dns_reason = check_dns(pkt, config)
    if dns_reason:
        reasons.append(f"Suspicious DNS: {dns_reason}")

    # Data spike check
    spike_reason = check_data_spike(pkt, config, traffic_db, local_ip)
    if spike_reason:
        reasons.append(f"Data spike: {spike_reason}")

    return reasons
