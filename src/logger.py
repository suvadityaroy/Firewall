import logging
import os
from datetime import datetime

class FirewallLogger:
    def __init__(self, log_dir='logs', log_level='INFO'):
        """Initialize firewall logger with separate log files."""
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Create timestamp for this session
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Configure main logger
        self.logger = logging.getLogger('firewall')
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Main log file (all events)
        main_handler = logging.FileHandler(
            os.path.join(log_dir, f'firewall_{timestamp}.log')
        )
        main_handler.setLevel(logging.DEBUG)
        main_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        main_handler.setFormatter(main_formatter)
        self.logger.addHandler(main_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Separate files for accepted/rejected/declined
        self.accepted_file = open(
            os.path.join(log_dir, f'accepted_{timestamp}.log'), 'a'
        )
        self.rejected_file = open(
            os.path.join(log_dir, f'rejected_{timestamp}.log'), 'a'
        )
        self.declined_file = open(
            os.path.join(log_dir, f'declined_{timestamp}.log'), 'a'
        )
        
    def log_packet(self, packet, direction, action, reason=''):
        """Log a packet processing event."""
        log_msg = (
            f"{direction.upper()} | {packet.String()} | "
            f"Action: {action} | {reason}"
        )
        
        # Log to main file
        if action == 'Accept':
            self.logger.info(log_msg)
            self.accepted_file.write(f"{datetime.now()} - {log_msg}\n")
            self.accepted_file.flush()
        elif action == 'Reject':
            self.logger.warning(log_msg)
            self.rejected_file.write(f"{datetime.now()} - {log_msg}\n")
            self.rejected_file.flush()
        elif action == 'Decline':
            self.logger.warning(log_msg)
            self.declined_file.write(f"{datetime.now()} - {log_msg}\n")
            self.declined_file.flush()
        else:
            self.logger.error(log_msg)
            
    def log_transmission(self, success, packet, direction):
        """Log final transmission result."""
        status = "SUCCESS" if success else "DROPPED"
        msg = f"Transmission {status}: {direction} {packet.String()}"
        
        if success:
            self.logger.info(msg)
        else:
            self.logger.warning(msg)
            
    def log_rule_reload(self, rule_type):
        """Log rule configuration reload."""
        self.logger.info(f"Reloaded {rule_type} rules from configuration")
        
    def close(self):
        """Close all log file handlers."""
        self.accepted_file.close()
        self.rejected_file.close()
        self.declined_file.close()
        for handler in self.logger.handlers:
            handler.close()
