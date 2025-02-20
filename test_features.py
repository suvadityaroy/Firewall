# Test script to verify new features
import sys
sys.path.insert(0, 'src')

print("Testing imports...")
from logger import FirewallLogger
from statistics import FirewallStats
from alerts import AlertSystem
from rule_engine import rule_engine

print("\n1. Testing Logger...")
logger = FirewallLogger(log_dir='test_logs', log_level='INFO')
print("   \u2713 Logger initialized")

print("\n2. Testing Statistics...")
stats = FirewallStats()
print("   \u2713 Statistics initialized")

print("\n3. Testing Alert System...")
alerts = AlertSystem()
print("   \u2713 Alert system initialized")

print("\n4. Testing Enhanced Rule Engine...")
r = rule_engine()

# Test wildcard matching
print("   Testing IP wildcards...")
assert r._match_ip('192.168.1.*', '192.168.1.100') == True
assert r._match_ip('192.168.1.*', '192.168.2.100') == False
print("   \u2713 Wildcard matching works")

# Test CIDR matching
print("   Testing CIDR notation...")
assert r._match_ip('192.168.1.0/24', '192.168.1.50') == True
assert r._match_ip('192.168.1.0/24', '192.168.2.50') == False
print("   \u2713 CIDR matching works")

# Test port range matching
print("   Testing port ranges...")
assert r._match_port('80-8080', '443') == True
assert r._match_port('80-8080', '9000') == False
assert r._match_port('443,80-8080', '80') == True
print("   \u2713 Port range matching works")

print("\n5. Testing statistics tracking...")
class MockPacket:
    def getSrcIP(self): return '192.168.1.1'
    def getDstIP(self): return '192.168.1.2'
    def getSrcPort(self): return '443'
    def getDstPort(self): return '80'
    def String(self): return 'Mock packet'

packet = MockPacket()
stats.record_packet(packet, 'inbound', 'Accept', 'Reject', 'TCP')
summary = stats.get_summary()
print(f"   Total packets: {summary['total_packets']}")
print(f"   Accepted: {summary['accepted']}, Rejected: {summary['rejected']}")
print("   \u2713 Statistics tracking works")

print("\n6. Cleanup...")
logger.close()
print("   \u2713 Logger closed")

print("\n" + "="*50)
print("ALL TESTS PASSED!")
print("="*50)
