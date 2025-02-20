# -*- coding: utf-8 -*-
from util import getIpAddress,getPort, isSrc
from tcp_packet import tcp_packet
from udp_packet import udp_packet
from rule_engine import rule_engine
from logger import FirewallLogger
from statistics import FirewallStats
from alerts import AlertSystem

def main(f, enable_logging=True, enable_stats=True, enable_alerts=True):
    """
    Main firewall processing loop with enhanced features.
    
    Args:
        f: File handle to packet data
        enable_logging: Enable logging to files
        enable_stats: Enable statistics tracking
        enable_alerts: Enable alert system
    """
    # Initialize components
    logger = FirewallLogger() if enable_logging else None
    stats = FirewallStats() if enable_stats else None
    alerts = AlertSystem() if enable_alerts else None
    r = rule_engine()
    
    packet_count = 0
    
    try:
        while(True):
            # Check for rule file modifications
            reloaded = r.reload_if_modified()
            if reloaded and logger:
                for rule_type in reloaded:
                    logger.log_rule_reload(rule_type)
            
            f.readline()
            f.readline()
            s = f.readline()
            
            if not s or len(s) < 10:  # End of file or invalid line
                break
                
            s = s[6:len(s)-2].split("|")
            
            if len(s) < 38:  # Ensure we have enough fields
                continue

            MACaddress =s[6]+":"+s[7]+":"+s[8]+":"+s[9]+":"+s[10]+":"+s[11] 
            protocol = "Unknown"

            if(s[23]== "06"):
                protocol = "TCP"
                packet = tcp_packet(MACaddress,\
                             getIpAddress(s[26:30]), \
                             getIpAddress(s[30:34]),\
                             getPort(s[34:36]), \
                             getPort(s[36:38]) )

            elif(s[23]== "11"):
                protocol = "UDP"
                packet = udp_packet(MACaddress,\
                             getIpAddress(s[26:30]), \
                             getIpAddress(s[30:34]),\
                             getPort(s[34:36]), \
                             getPort(s[36:38]) )
            else:
                continue
                
            print(packet.String())
            f.readline()

            packet_count += 1
            
            #Check if the src of the packet is my device
            #Then the packet is travelling outside my network
            isSuccess = False
            direction = ""
            
            if(isSrc(['f8','34','41','21','87','7a'],s[6:12])):
                direction = "outbound"
                print("packet going out of our server..")
                
                src_action = r.checkOutboundRules(packet.getSrcIP(), packet.getSrcPort())
                dst_action = r.checkOutboundRules(packet.getDstIP(), packet.getDstPort())
                
                print("source ip:{} and port:{} will {}".format(packet.getSrcIP(),\
                                                                          packet.getSrcPort(),\
                                        src_action))
                print("Destination ip:{} and port:{} will {}".format(packet.getDstIP(),\
                                                                          packet.getDstPort(),\
                                        dst_action))

                isSuccess = src_action == 'Accept' and dst_action == 'Accept'
                
                # Log individual endpoint decisions
                if logger:
                    logger.log_packet(packet, direction, src_action, 
                                    f"Source: {packet.getSrcIP()}:{packet.getSrcPort()}")
                    logger.log_packet(packet, direction, dst_action,
                                    f"Destination: {packet.getDstIP()}:{packet.getDstPort()}")
                
                # Track statistics
                if stats:
                    stats.record_packet(packet, direction, src_action, dst_action, protocol)
                
                # Check for alerts
                if alerts:
                    alerts.check_and_alert(packet.getSrcIP(), src_action, packet.String())
                    alerts.check_and_alert(packet.getDstIP(), dst_action, packet.String())

            else:
                direction = "inbound"
                print("packet comes to our server..")
                
                src_action = r.checkInboundRules(packet.getSrcIP(), packet.getSrcPort())
                dst_action = r.checkInboundRules(packet.getDstIP(), packet.getDstPort())
                
                print("source ip:{} and port:{} will {}".format(packet.getSrcIP(),\
                                                                          packet.getSrcPort(),\
                                        src_action))
                print("Destination ip:{} and port:{} will {}".format(packet.getDstIP(),\
                                                                          packet.getDstPort(),\
                                        dst_action))
                
                isSuccess = src_action == 'Accept' and dst_action == 'Accept'
                
                # Log individual endpoint decisions
                if logger:
                    logger.log_packet(packet, direction, src_action,
                                    f"Source: {packet.getSrcIP()}:{packet.getSrcPort()}")
                    logger.log_packet(packet, direction, dst_action,
                                    f"Destination: {packet.getDstIP()}:{packet.getDstPort()}")
                
                # Track statistics
                if stats:
                    stats.record_packet(packet, direction, src_action, dst_action, protocol)
                
                # Check for alerts
                if alerts:
                    alerts.check_and_alert(packet.getSrcIP(), src_action, packet.String())
                    alerts.check_and_alert(packet.getDstIP(), dst_action, packet.String())

            if(isSuccess):
                print("Packet transmission successfull")
            else:
                print("Packet transmission unsuccessfull!!! Packet Dropped")
                
            # Log transmission result
            if logger:
                logger.log_transmission(isSuccess, packet, direction)

            print("\n\n")
            
    except KeyboardInterrupt:
        print("\n\nFirewall stopped by user")
    except Exception as e:
        print(f"\n\nError processing packets: {e}")
    finally:
        # Cleanup and show summary
        if logger:
            logger.close()
            print("Logs saved to logs/ directory")
            
        if stats:
            stats.print_summary()
            json_file = stats.export_json()
            csv_file = stats.export_csv()
            print(f"Statistics exported to:\n  - {json_file}\n  - {csv_file}")
            
        if alerts:
            suspicious = alerts.get_suspicious_ips()
            if suspicious:
                print("\nSuspicious IPs detected:")
                for ip, data in suspicious.items():
                    print(f"  {ip}: {data['count']} blocks since {data['first_blocked']}")
        
        print(f"\nTotal packets processed: {packet_count}")


'''
f = open('../packets/tcp.txt','r')
g = open('../packets/udp.txt','r')  
main(f)

'''
