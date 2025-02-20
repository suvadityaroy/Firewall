import json
import csv
from collections import defaultdict
from datetime import datetime

class FirewallStats:
    def __init__(self):
        """Initialize statistics tracker."""
        self.stats = {
            'total_packets': 0,
            'accepted': 0,
            'rejected': 0,
            'declined': 0,
            'no_rule': 0,
            'inbound': 0,
            'outbound': 0,
            'by_ip': defaultdict(lambda: {
                'accepted': 0, 'rejected': 0, 'declined': 0, 'no_rule': 0
            }),
            'by_port': defaultdict(lambda: {
                'accepted': 0, 'rejected': 0, 'declined': 0, 'no_rule': 0
            }),
            'by_protocol': defaultdict(int),
            'suspicious_ips': defaultdict(int),  # IPs with high reject count
            'start_time': datetime.now().isoformat()
        }
        
    def record_packet(self, packet, direction, src_action, dst_action, protocol='TCP'):
        """Record a packet processing event."""
        self.stats['total_packets'] += 1
        
        # Direction
        if direction.lower() == 'inbound':
            self.stats['inbound'] += 1
        else:
            self.stats['outbound'] += 1
            
        # Protocol
        self.stats['by_protocol'][protocol] += 1
        
        # Track source
        self._update_action_stats(src_action, packet.getSrcIP(), packet.getSrcPort())
        
        # Track destination
        self._update_action_stats(dst_action, packet.getDstIP(), packet.getDstPort())
        
    def _update_action_stats(self, action, ip, port):
        """Update statistics for a specific action."""
        action_lower = action.lower()
        
        if 'accept' in action_lower:
            self.stats['accepted'] += 1
            self.stats['by_ip'][ip]['accepted'] += 1
            self.stats['by_port'][port]['accepted'] += 1
        elif 'reject' in action_lower:
            self.stats['rejected'] += 1
            self.stats['by_ip'][ip]['rejected'] += 1
            self.stats['by_port'][port]['rejected'] += 1
            self.stats['suspicious_ips'][ip] += 1
        elif 'decline' in action_lower:
            self.stats['declined'] += 1
            self.stats['by_ip'][ip]['declined'] += 1
            self.stats['by_port'][port]['declined'] += 1
            self.stats['suspicious_ips'][ip] += 1
        else:
            self.stats['no_rule'] += 1
            self.stats['by_ip'][ip]['no_rule'] += 1
            self.stats['by_port'][port]['no_rule'] += 1
            
    def get_summary(self):
        """Get statistics summary."""
        return {
            'total_packets': self.stats['total_packets'],
            'accepted': self.stats['accepted'],
            'rejected': self.stats['rejected'],
            'declined': self.stats['declined'],
            'no_rule': self.stats['no_rule'],
            'inbound': self.stats['inbound'],
            'outbound': self.stats['outbound'],
            'protocols': dict(self.stats['by_protocol']),
            'top_suspicious_ips': self.get_top_suspicious_ips(5)
        }
        
    def get_top_suspicious_ips(self, limit=10):
        """Get IPs with most rejects/declines."""
        sorted_ips = sorted(
            self.stats['suspicious_ips'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_ips[:limit]
        
    def get_ip_stats(self, ip):
        """Get statistics for specific IP."""
        return dict(self.stats['by_ip'].get(ip, {}))
        
    def get_port_stats(self, port):
        """Get statistics for specific port."""
        return dict(self.stats['by_port'].get(port, {}))
        
    def export_json(self, filename='stats/firewall_stats.json'):
        """Export statistics to JSON file."""
        import os
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        export_data = {
            **self.get_summary(),
            'by_ip': {ip: dict(stats) for ip, stats in self.stats['by_ip'].items()},
            'by_port': {port: dict(stats) for port, stats in self.stats['by_port'].items()},
            'end_time': datetime.now().isoformat(),
            'start_time': self.stats['start_time']
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
            
        return filename
        
    def export_csv(self, filename='stats/firewall_stats.csv'):
        """Export IP statistics to CSV file."""
        import os
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Accepted', 'Rejected', 'Declined', 'No Rule'])
            
            for ip, stats in self.stats['by_ip'].items():
                writer.writerow([
                    ip,
                    stats['accepted'],
                    stats['rejected'],
                    stats['declined'],
                    stats['no_rule']
                ])
                
        return filename
        
    def print_summary(self):
        """Print statistics summary to console."""
        summary = self.get_summary()
        
        print("\n" + "="*60)
        print("FIREWALL STATISTICS SUMMARY")
        print("="*60)
        print(f"Total Packets Processed: {summary['total_packets']}")
        print(f"  - Accepted: {summary['accepted']}")
        print(f"  - Rejected: {summary['rejected']}")
        print(f"  - Declined: {summary['declined']}")
        print(f"  - No Rule:  {summary['no_rule']}")
        print(f"\nDirection:")
        print(f"  - Inbound:  {summary['inbound']}")
        print(f"  - Outbound: {summary['outbound']}")
        print(f"\nProtocols: {summary['protocols']}")
        
        if summary['top_suspicious_ips']:
            print(f"\nTop Suspicious IPs (most rejects/declines):")
            for ip, count in summary['top_suspicious_ips']:
                print(f"  - {ip}: {count} blocked attempts")
                
        print("="*60 + "\n")
