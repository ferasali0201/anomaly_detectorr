from datetime import datetime
from rich import print
from scapy.all import IP
import time
import json

def show_alert(pkt, reasons, process_name, log_path=None):
    if not pkt.haslayer(IP):
        return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src = pkt[IP].src
    dst = pkt[IP].dst

    print(f"[bold red]{ts}[/bold red] | [cyan]{src}[/cyan] → [green]{dst}[/green]")
    for reason in reasons:
        print(f"  ⚠️ [yellow]{reason}[/yellow]")

    if log_path:
        alert = {
            "timestamp": ts,
            "process": process_name,
            "source": src,
            "destination": dst,
            "reasons": reasons
        }
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps(alert) + "\n")
        except Exception as e:
            print(f"[DEBUG] Failed to write alert to log: {e}")
