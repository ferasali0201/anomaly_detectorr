from scapy.all import DNS

def check_dns(pkt, config):
    if pkt.haslayer(DNS) and pkt[DNS].qd:
        try:
            qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip('.')
            for keyword in config["thresholds"]["suspicious_dns_keywords"]:
                if keyword.lower() in qname.lower():
                    return f"Suspicious DNS lookup: {qname}"
        except Exception:
            pass
    return None
