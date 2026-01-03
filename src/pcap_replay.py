from scapy.all import sniff, rdpcap
from src.analyzer import PacketAnalyzer
import os

class PCAPReplay:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.analyzer = PacketAnalyzer()

    def run(self):
        if not os.path.exists(self.pcap_file):
            print(f"[!] PCAP file not found: {self.pcap_file}")
            return

        print(f"[*] Replaying PCAP: {self.pcap_file}...")
        
        # We can use rdpcap to read all and iterate, or sniff(offline=...)
        # sniff(offline=...) is better for large files as it streams.
        
        try:
            sniff(offline=self.pcap_file, prn=self.analyzer.process_packet, store=0)
            print("[*] PCAP Replay finished.")
        except Exception as e:
            print(f"[!] Error processing PCAP: {e}")
