# -*- coding: utf-8 -*-

import sys
import os
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__) + '/src' )))

from core import main

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Python Firewall - Network packet analysis and rule enforcement',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py                          # Run with TCP packets (default)
  python main.py --udp                    # Run with UDP packets
  python main.py --no-logging             # Disable logging
  python main.py --no-stats               # Disable statistics
  python main.py --no-alerts              # Disable alerts
  python main.py --file packets/custom.txt # Use custom packet file
        '''
    )
    
    parser.add_argument(
        '--udp',
        action='store_true',
        help='Process UDP packets instead of TCP'
    )
    
    parser.add_argument(
        '--file',
        type=str,
        default=None,
        help='Custom packet file to process'
    )
    
    parser.add_argument(
        '--no-logging',
        action='store_true',
        help='Disable file logging'
    )
    
    parser.add_argument(
        '--no-stats',
        action='store_true',
        help='Disable statistics tracking'
    )
    
    parser.add_argument(
        '--no-alerts',
        action='store_true',
        help='Disable alert system'
    )
    
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    # Determine packet file to use
    if args.file:
        packet_file = args.file
    elif args.udp:
        packet_file = 'packets/udp.txt'
    else:
        packet_file = 'packets/tcp.txt'
    
    # Check if file exists
    if not os.path.exists(packet_file):
        print(f"Error: Packet file '{packet_file}' not found!")
        sys.exit(1)
    
    print("="*60)
    print("Python Firewall - Starting")
    print("="*60)
    print(f"Packet file: {packet_file}")
    print(f"Logging: {'Disabled' if args.no_logging else 'Enabled'}")
    print(f"Statistics: {'Disabled' if args.no_stats else 'Enabled'}")
    print(f"Alerts: {'Disabled' if args.no_alerts else 'Enabled'}")
    print("="*60 + "\n")
    
    try:
        with open(packet_file, 'r') as f:
            main(
                f,
                enable_logging=not args.no_logging,
                enable_stats=not args.no_stats,
                enable_alerts=not args.no_alerts
            )
    except FileNotFoundError:
        print(f"Error: Could not open file '{packet_file}'")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nFirewall stopped by user (Ctrl+C)")
        sys.exit(0)

