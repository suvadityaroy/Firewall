import configparser
import ipaddress
import os
from datetime import datetime

class rule_engine():
    def __init__(self):
        self.in_config = configparser.ConfigParser()
        self.out_config = configparser.ConfigParser()
        self.in_config.read('src/inbound rules.ini')
        self.out_config.read('src/outbound rules.ini')
        self.last_modified = {
            'inbound': os.path.getmtime('src/inbound rules.ini') if os.path.exists('src/inbound rules.ini') else 0,
            'outbound': os.path.getmtime('src/outbound rules.ini') if os.path.exists('src/outbound rules.ini') else 0
        }
        
    def reload_if_modified(self):
        """Reload rules if configuration files have been modified."""
        reloaded = []
        
        if os.path.exists('src/inbound rules.ini'):
            mtime = os.path.getmtime('src/inbound rules.ini')
            if mtime > self.last_modified['inbound']:
                self.in_config.read('src/inbound rules.ini')
                self.last_modified['inbound'] = mtime
                reloaded.append('inbound')
                
        if os.path.exists('src/outbound rules.ini'):
            mtime = os.path.getmtime('src/outbound rules.ini')
            if mtime > self.last_modified['outbound']:
                self.out_config.read('src/outbound rules.ini')
                self.last_modified['outbound'] = mtime
                reloaded.append('outbound')
                
        return reloaded
    
    def _match_ip(self, rule_ip, packet_ip):
        """Match IP with support for wildcards and CIDR notation."""
        try:
            # Exact match
            if rule_ip == packet_ip:
                return True
                
            # Wildcard match (e.g., 192.168.1.*)
            if '*' in rule_ip:
                rule_pattern = rule_ip.replace('.', r'\.').replace('*', '.*')
                import re
                if re.match(f'^{rule_pattern}$', packet_ip):
                    return True
                    
            # CIDR notation (e.g., 192.168.1.0/24)
            if '/' in rule_ip:
                network = ipaddress.ip_network(rule_ip, strict=False)
                ip_obj = ipaddress.ip_address(packet_ip)
                if ip_obj in network:
                    return True
                    
        except (ValueError, ipaddress.AddressValueError):
            pass
            
        return False
        
    def _match_port(self, rule_ports, packet_port):
        """Match port with support for ranges (e.g., 80-8080)."""
        port_list = rule_ports.split(',')
        
        for port_spec in port_list:
            port_spec = port_spec.strip()
            
            # Port range (e.g., 80-8080)
            if '-' in port_spec and port_spec.count('-') == 1:
                try:
                    start, end = port_spec.split('-')
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    packet_port_int = int(packet_port)
                    
                    if start_port <= packet_port_int <= end_port:
                        return True
                except ValueError:
                    pass
                    
            # Exact match
            elif port_spec == packet_port:
                return True
                
        return False

    def checkInboundRules(self, ip_address, port):
        """Check inbound rules with enhanced matching (wildcards, CIDR, port ranges)."""
        # Check accepting rules
        for rule_ip in self.in_config['Accepting ip']:
            if self._match_ip(rule_ip, ip_address):
                rule_ports = self.in_config['Accepting ip'][rule_ip]
                if self._match_port(rule_ports, port):
                    return "Accept"

        # Check declining rules
        for rule_ip in self.in_config['Declining ip']:
            if self._match_ip(rule_ip, ip_address):
                rule_ports = self.in_config['Declining ip'][rule_ip]
                if self._match_port(rule_ports, port):
                    return "Decline"

        # Check rejecting rules
        for rule_ip in self.in_config['Rejecting ip']:
            if self._match_ip(rule_ip, ip_address):
                rule_ports = self.in_config['Rejecting ip'][rule_ip]
                if self._match_port(rule_ports, port):
                    return "Reject"

        return "No rule associated!!!! Please assign a rule"



    def checkOutboundRules(self, ip_address, port):
        """Check outbound rules with enhanced matching (wildcards, CIDR, port ranges)."""
        # Check accepting rules
        for rule_ip in self.out_config['Accepting ip']:
            if self._match_ip(rule_ip, ip_address):
                rule_ports = self.out_config['Accepting ip'][rule_ip]
                if self._match_port(rule_ports, port):
                    return "Accept"

        # Check declining rules
        for rule_ip in self.out_config['Declining ip']:
            if self._match_ip(rule_ip, ip_address):
                rule_ports = self.out_config['Declining ip'][rule_ip]
                if self._match_port(rule_ports, port):
                    return "Decline"

        # Check rejecting rules
        for rule_ip in self.out_config['Rejecting ip']:
            if self._match_ip(rule_ip, ip_address):
                rule_ports = self.out_config['Rejecting ip'][rule_ip]
                if self._match_port(rule_ports, port):
                    return "Reject"

        return "No rule associated!!!! Please assign a rule"
    


'''
r = rule_engine()
print(r.checkOutboundRules('192.168.1.6','63449'))
print(r.checkInboundRules('54.192.151.48','443'))
'''
'''
print(r.checkOutboundRules('192.168.1.6','63439'))  # should return Reject
print(r.checkOutboundRules('192.168.1.6','55173'))  # should return Accept
print(r.checkOutboundRules('192.168.1.6','57762'))  # should return Decline
print(r.checkOutboundRules('192.168.2.6','57762'))  # should return No rule associated !!! (No Ip)
print(r.checkOutboundRules('192.168.2.6','1'))      # should return No rule associated !!! (No Port)



print(r.checkInboundRules('192.168.1.4','2054'))  # should return Reject
print(r.checkInboundRules('142.250.4.93','443'))  # should return Accept
print(r.checkInboundRules('198.252.206.25','443'))  # should return Decline
print(r.checkInboundRules('192.168.2.0','443'))  # should return No rule associated !!! (No Ip)
print(r.checkInboundRules('192.168.1.4','1')) # should return No rule associated !!! (No Ip)
'''
