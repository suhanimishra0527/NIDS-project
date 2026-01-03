from scapy.all import send, IP, TCP, Raw, conf, get_if_list
import sys
import time
import random

def get_target_iface():
    try:
        return conf.route.route("8.8.8.8")[0]
    except:
        return get_if_list()[0]

def simulate_attack():
    target_ip = "192.168.1.50" 
    print(f"[*] Sending attack packets...")
    
    # 1. SQL Injection (Signature)
    payload_sqli = "User: admin' UNION SELECT * FROM users --"
    pkt1 = IP(dst=target_ip)/TCP(dport=80)/Raw(load=payload_sqli)
    send(pkt1, verbose=0)
    print(f"[+] Sent SQL Injection payload")
    
    time.sleep(0.5)

    # 2. XSS (Signature)
    payload_xss = "<script>alert(1)</script>"
    pkt2 = IP(dst=target_ip)/TCP(dport=80)/Raw(load=payload_xss)
    send(pkt2, verbose=0)
    print(f"[+] Sent XSS payload")

    # 3. Port Scan (10+ distinct ports)
    print("[*] Simulating Port Scan...")
    for port in range(1024, 1040):
        # Syn scan style
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
    print("[+] Sent Port Scan (16 ports)")

    # 4. Brute Force (20+ attempts on port 22)
    print("[*] Simulating SSH Brute Force...")
    for i in range(25):
        pkt = IP(dst=target_ip)/TCP(dport=22, flags="S")
        send(pkt, verbose=0)
    print("[+] Sent SSH Brute Force (25 attempts)")

    print("[*] Attack simulation completed.")

if __name__ == "__main__":
    simulate_attack()
