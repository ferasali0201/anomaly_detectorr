from scapy.all import IP

def check_data_spike(pkt, config, traffic_db, local_ip):
    if not pkt.haslayer(IP):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    length = len(pkt)
    threshold_bytes = config["thresholds"]["data_spike_kb"] * 1024

    # Track outbound only
    if src_ip == local_ip:
        traffic_db.setdefault(dst_ip, 0)
        traffic_db[dst_ip] += length

        if traffic_db[dst_ip] > threshold_bytes:
            kb = traffic_db[dst_ip] / 1024
            return f"{kb:.2f} KB to {dst_ip}"

    return None
