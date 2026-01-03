from scapy.all import sniff
from src.analyzer import PacketAnalyzer

class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface
        self.analyzer = PacketAnalyzer()

    def packet_callback(self, packet):
        """
        This function is called for every packet captured.
        """
        # We pass the raw packet to the analyzer
        self.analyzer.process_packet(packet)

    def start_sniffing(self):
        print(f"[*] Starting packet capture on {self.interface or 'default interface'}...")
        # 'store=0' prevents memory leaks by not keeping packets in RAM
        sniff(iface=self.interface, prn=self.packet_callback, store=0)
