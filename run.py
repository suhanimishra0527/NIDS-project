import sys
import os
import argparse
from scapy.all import conf, get_if_list

# Add current directory to path
sys.path.append(os.getcwd())

from src.utils import load_config
from src.capture import PacketCapture
from src.pcap_replay import PCAPReplay
from src.alerts import setup_logger

def get_default_iface_name(config_iface=None):
    if config_iface:
        return config_iface
    print("[*] Auto-detecting best network interface...")
    try:
        return conf.route.route("8.8.8.8")[0]
    except Exception as e:
        print(f"[!] Could not auto-detect interface: {e}")
        return get_if_list()[0]

def start_dashboard():
    print("[*] Starting Web Dashboard...")
    from dashboard.app import app
    app.run(debug=True, port=5000, use_reloader=False)

def main():
    parser = argparse.ArgumentParser(description="NIDS - Network Intrusion Detection System")
    parser.add_argument("--live", action="store_true", help="Start live packet capture (default)")
    parser.add_argument("--pcap", type=str, help="Replay a PCAP file for analysis")
    parser.add_argument("--dashboard", action="store_true", help="Start the Web Dashboard")
    
    args = parser.parse_args()

    # Load Config
    config = load_config()
    if not config:
        sys.exit(1)

    # Logging Setup
    log_file = os.path.join(config['logging']['log_dir'], config['logging']['filename'])
    setup_logger(os.path.join(os.getcwd(), log_file))

    if args.dashboard:
        start_dashboard()
        return

    if args.pcap:
        replay = PCAPReplay(args.pcap)
        replay.run()
        return

    # Default: Live Capture
    configured_iface = config.get('network', {}).get('interface')
    iface_name = get_default_iface_name(configured_iface)
    
    if hasattr(iface_name, "name"):
         iface_name = iface_name.name
    
    print(f"[*] Found active interface: {iface_name}")
    print("[*] Starting NIDS in Live Mode...")
    
    try:
        capture = PacketCapture(interface=iface_name)
        capture.start_sniffing()
    except KeyboardInterrupt:
        print("\n[*] Stopping NIDS...")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error during capture: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()