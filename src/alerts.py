import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from datetime import datetime

class AlertSystem:
    def __init__(self, config_file='src/alert_config.json'):
        """Initialize alert system with configuration."""
        self.config = self._load_config(config_file)
        self.alert_counts = defaultdict(int)
        self.blocked_ips = {}  # IP -> first block time
        
    def _load_config(self, config_file):
        """Load alert configuration from JSON file."""
        default_config = {
            'enabled': True,
            'threshold': 10,  # Number of blocks before alert
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'from_email': '',
                'to_email': '',
                'password': ''
            },
            'webhook': {
                'enabled': False,
                'url': ''
            },
            'console_alerts': True
        }
        
        try:
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)
                default_config.update(loaded_config)
        except FileNotFoundError:
            # Save default config
            import os
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
                
        return default_config
        
    def check_and_alert(self, ip, action, packet_info=''):
        """Check if an alert should be triggered for suspicious activity."""
        if not self.config['enabled']:
            return
            
        # Only alert on blocks (reject/decline)
        if action.lower() not in ['reject', 'decline']:
            return
            
        # Increment block count
        self.alert_counts[ip] += 1
        
        # Track first block time
        if ip not in self.blocked_ips:
            self.blocked_ips[ip] = datetime.now()
            
        # Check threshold
        if self.alert_counts[ip] >= self.config['threshold']:
            self._send_alert(ip, self.alert_counts[ip], packet_info)
            
    def _send_alert(self, ip, block_count, packet_info):
        """Send alert through configured channels."""
        alert_message = (
            f"FIREWALL ALERT: Suspicious Activity Detected\n"
            f"IP Address: {ip}\n"
            f"Total Blocks: {block_count}\n"
            f"First Blocked: {self.blocked_ips[ip]}\n"
            f"Latest Event: {datetime.now()}\n"
            f"Packet Info: {packet_info}\n"
        )
        
        # Console alert
        if self.config['console_alerts']:
            print("\n" + "!"*60)
            print(alert_message)
            print("!"*60 + "\n")
            
        # Email alert
        if self.config['email']['enabled']:
            self._send_email_alert(alert_message, ip)
            
        # Webhook alert
        if self.config['webhook']['enabled']:
            self._send_webhook_alert(alert_message, ip, block_count)
            
    def _send_email_alert(self, message, ip):
        """Send email alert."""
        try:
            email_config = self.config['email']
            
            msg = MIMEMultipart()
            msg['From'] = email_config['from_email']
            msg['To'] = email_config['to_email']
            msg['Subject'] = f"Firewall Alert: Suspicious IP {ip}"
            
            msg.attach(MIMEText(message, 'plain'))
            
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                server.starttls()
                server.login(email_config['from_email'], email_config['password'])
                server.send_message(msg)
                
            print(f"Email alert sent for IP: {ip}")
        except Exception as e:
            print(f"Failed to send email alert: {e}")
            
    def _send_webhook_alert(self, message, ip, block_count):
        """Send webhook alert (e.g., to Slack, Discord, etc.)."""
        try:
            import requests
            
            payload = {
                'text': message,
                'ip': ip,
                'block_count': block_count,
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(
                self.config['webhook']['url'],
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"Webhook alert sent for IP: {ip}")
            else:
                print(f"Webhook alert failed: {response.status_code}")
                
        except Exception as e:
            print(f"Failed to send webhook alert: {e}")
            
    def get_suspicious_ips(self):
        """Get list of IPs that have been blocked multiple times."""
        return {
            ip: {
                'count': count,
                'first_blocked': self.blocked_ips[ip].isoformat()
            }
            for ip, count in self.alert_counts.items()
            if count > 0
        }
        
    def reset_counts(self):
        """Reset alert counts (for testing or periodic resets)."""
        self.alert_counts.clear()
        self.blocked_ips.clear()
