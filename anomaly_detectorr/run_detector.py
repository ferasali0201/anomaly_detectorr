import argparse, yaml
from pathlib import Path
from queue import Queue
from threading import Thread
from sniffer import start_sniffing
from analyzer import analyze_packet
from process_mapper import get_process_by_port
from alert import show_alert
from scapy.all import IP, TCP, UDP
from rich import print
import netifaces

def show_banner():
    banner = """
[bold red]     *********** ***********   [/bold red]
[bold red]   ************* ************* [/bold red]
[bold red]  ************** ****************[/bold red]
[bold red]  *********** [/bold red][white]██████[/white][bold red] ***********[/bold red]
[bold red]   ********** [/bold red][white]██╔═══╝[/white][bold red]********** [/bold red]
[bold red]    ********* [/bold red][white]█████╗[/white][bold red] *********[/bold red]
[bold red]     ******** [/bold red][white]██╔══╝[/white][bold red]********[/bold red]
[bold red]      ******* [/bold red][white]██║[/white][bold red] *******[/bold red]
[bold red]       ****** [/bold red][white]╚═╝[/white][bold red]******[/bold red]
[bold red]          ***********       [/bold red]
[bold red]           *********             [/bold red]
[bold red]            ******                [/bold red]
[bold red]             ***                [/bold red]
[bold red]              *                [/bold red]

[green]Real-Time Network Anomaly Detector[/green]
"""
    print(banner)

def parse_args():
    parser = argparse.ArgumentParser(description="Real-Time Network Anomaly Detector")
    parser.add_argument("--interface", required=True, help="Network interface to monitor")
    parser.add_argument("--log", default=None, help="Path to log file")
    parser.add_argument("--reputation", choices=["on", "off"], default="on", help="Enable reputation checks")
    return parser.parse_args()

def load_config(args):
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    if args.reputation == "off":
        config["reputation_services"]["abuseipdb"]["enabled"] = False
    return config

def get_local_ip(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["addr"]

def monitor(config, args):
    packet_queue = Queue()
    Thread(target=start_sniffing, args=(packet_queue, args.interface), daemon=True).start()
    print(f"[*] Monitoring traffic on [cyan]{args.interface}[/cyan]...")

    if args.log:
        Path(args.log).touch()

    local_ip = get_local_ip(args.interface)

    while True:
        pkt = packet_queue.get()
        reasons = analyze_packet(pkt, config, local_ip)
        if reasons:
            port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else None
            ip = pkt[IP].dst if IP in pkt else "Unknown"
            proc = get_process_by_port(ip, port) if port else None
            show_alert(pkt, reasons, proc, log_path=args.log)

if __name__ == "__main__":
    show_banner()
    args = parse_args()
    config = load_config(args)
    monitor(config, args)
