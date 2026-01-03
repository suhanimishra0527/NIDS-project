"""
NIDS - Network Intrusion Detection System
Entry point with mode separation for cloud and local deployment.

Modes:
    --dashboard : Web Dashboard only (cloud-safe, no Scapy required)
    --live      : Live packet capture (requires Scapy + admin privileges)
    --pcap      : Replay a PCAP file (requires Scapy)
"""
import sys
import os
import argparse

# Add current directory to path
sys.path.append(os.getcwd())


def start_dashboard():
    """
    Start the Flask web dashboard.
    This mode is cloud-safe and does NOT require Scapy.
    """
    print("[*] Starting Web Dashboard...")
    from dashboard.app import app
    
    # Use PORT from environment (Render sets this), default to 5000
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f"[*] Dashboard running on http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)


def start_live_capture(config):
    """
    Start live packet capture mode.
    Scapy is imported ONLY when this function is called.
    Requires: scapy, admin/root privileges
    """
    # Lazy import - Scapy only loaded when live mode is used
    try:
        from scapy.all import conf, get_if_list
    except ImportError:
        print("[!] ERROR: Scapy is not installed.")
        print("[!] Install it with: pip install scapy")
        print("[!] For cloud deployment, use --dashboard mode instead.")
        sys.exit(1)
    
    from src.capture import PacketCapture
    
    def get_default_iface_name(config_iface=None):
        if config_iface:
            return config_iface
        print("[*] Auto-detecting best network interface...")
        try:
            return conf.route.route("8.8.8.8")[0]
        except Exception as e:
            print(f"[!] Could not auto-detect interface: {e}")
            return get_if_list()[0]
    
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
    except PermissionError:
        print("[!] ERROR: Permission denied. Run with administrator/root privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during capture: {e}")
        sys.exit(1)


def start_pcap_replay(pcap_file):
    """
    Replay a PCAP file for analysis.
    Scapy is imported ONLY when this function is called.
    Requires: scapy
    """
    # Lazy import - Scapy only loaded when pcap mode is used
    try:
        from scapy.all import sniff  # noqa: F401
    except ImportError:
        print("[!] ERROR: Scapy is not installed.")
        print("[!] Install it with: pip install scapy")
        sys.exit(1)
    
    from src.pcap_replay import PCAPReplay
    
    replay = PCAPReplay(pcap_file)
    replay.run()


def main():
    parser = argparse.ArgumentParser(
        description="NIDS - Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --dashboard    Start web dashboard (cloud-safe, no packet capture)
  --live         Start live packet capture (requires Scapy + privileges)
  --pcap FILE    Replay a PCAP file for analysis (requires Scapy)

Examples:
  python run.py --dashboard          # Cloud/Render deployment
  python run.py --live               # Local live detection
  python run.py --pcap capture.pcap  # Analyze PCAP file
        """
    )
    parser.add_argument("--live", action="store_true", 
                        help="Start live packet capture (requires Scapy)")
    parser.add_argument("--pcap", type=str, 
                        help="Replay a PCAP file for analysis")
    parser.add_argument("--dashboard", action="store_true", 
                        help="Start the Web Dashboard (cloud-safe)")
    
    args = parser.parse_args()

    # Dashboard mode - cloud-safe, no config/logging needed
    if args.dashboard:
        start_dashboard()
        return

    # For live/pcap modes, we need config and logging
    from src.utils import load_config
    from src.alerts import setup_logger
    
    config = load_config()
    if not config:
        sys.exit(1)

    # Logging Setup
    log_file = os.path.join(config['logging']['log_dir'], config['logging']['filename'])
    setup_logger(os.path.join(os.getcwd(), log_file))

    if args.pcap:
        start_pcap_replay(args.pcap)
        return

    # Default: Live Capture (if no flags specified, or --live)
    start_live_capture(config)


if __name__ == "__main__":
    main()