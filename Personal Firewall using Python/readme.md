# 🔥 Python Firewall Project

A simple packet-sniffing firewall built with **Python** and **Scapy** that allows or blocks network traffic based on custom rules defined in a YAML file.

---

## 📌 Features
- Sniffs incoming and outgoing packets in real-time.
- Supports **TCP, UDP, and ICMP** filtering.
- Rule-based system using `rules.yml`:
  - Block specific ports (e.g., Telnet).
  - Block traffic from specific IP addresses.
  - Allow specific protocols/ports (e.g., DNS).
- Console output with **colored logs** (using `rich`).


