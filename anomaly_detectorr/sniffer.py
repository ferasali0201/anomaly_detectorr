from scapy.all import sniff, IP, TCP, UDP, DNS

def start_sniffing(packet_queue, iface=None):
    def handle_packet(pkt):
        
        if IP in pkt and (TCP in pkt or UDP in pkt or pkt.haslayer(DNS)):
            packet_queue.put(pkt)

    
    sniff(
        iface=iface,
        filter="tcp or udp port 53",
        prn=handle_packet,
        store=False
    )
