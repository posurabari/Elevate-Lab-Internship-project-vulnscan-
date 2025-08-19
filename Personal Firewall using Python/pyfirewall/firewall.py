from scapy.all import sniff, IP, TCP, UDP
import yaml
from rich.console import Console

console = Console()

# Load rules from rules.yml
with open("rules.yml", "r") as f:
    RULES = yaml.safe_load(f)

if not RULES:   # Safety check
    RULES = {"default": "allow", "rules": []}


def decide(pkt):
    for r in RULES.get("rules", []):
        # protocol match
        if "proto" in r:
            if r["proto"].lower() == "tcp" and not pkt.haslayer(TCP):
                continue
            if r["proto"].lower() == "udp" and not pkt.haslayer(UDP):
                continue

        # destination port
        if "dst_port" in r:
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else None
            if dport != r["dst_port"]:
                continue

        # source IP
        if "src_ip" in r:
            if pkt.haslayer(IP) and pkt[IP].src != r["src_ip"]:
                continue

        return r.get("action", RULES.get("default", "allow"))

    return RULES.get("default", "allow")


def handler(pkt):
    action = decide(pkt)
    if action == "block":
        console.print(f"[red]BLOCKED:[/red] {pkt.summary()}")
    else:
        console.print(f"[green]ALLOWED:[/green] {pkt.summary()}")


if __name__ == "__main__":
    console.print("[bold cyan]Firewall started... sniffing packets[/bold cyan]")
    sniff(prn=handler, store=False)
