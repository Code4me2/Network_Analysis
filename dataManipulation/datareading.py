from scapy.all import rdpcap, IP, TCP, UDP, DNSQR, DNSRR, TLS
import pandas as pd
import pyshark
import math
from collections import Counter

pcap_file = 'wireshark_file.pcapng'

# For Scapy: Load packets for general analysis
packets = rdpcap(pcap_file)

# For PyShark: Load the same file with filtering for HTTP/HTTPS traffic
cap = pyshark.FileCapture(pcap_file, display_filter="http or tls")

packets_data = []  # General packet data
http_data = []     # HTTP-specific data

# Extracting HTTP/HTTPS details with PyShark
for packet in cap:
    try:
        protocol = packet.highest_layer
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport

        if protocol == 'HTTP':
            http_method = packet.http.get_field_value('request_method') if 'request_method' in packet.http.field_names else 'N/A'
            http_host = packet.http.host if 'host' in packet.http.field_names else 'N/A'
            http_uri = packet.http.request_full_uri if 'request_full_uri' in packet.http.field_names else 'N/A'
            http_user_agent = packet.http.user_agent if 'user_agent' in packet.http.field_names else 'N/A'
            
            http_data.append({
                'timestamp': packet.sniff_timestamp,
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'http_method': http_method,
                'http_host': http_host,
                'http_uri': http_uri,
                'http_user_agent': http_user_agent
            })
    except AttributeError:
        # This handles packets that might be missing expected attributes
        continue

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy -= - p_x * math.log2(p_x)
    return entropy

# Known encypted service ports
encrypted_ports = [443, 993, 995, 22, 990, 989, 465, 500, 4500, 1194, 3389, 853, 8883, 636, 21]

# Processing general packet data with Scapy
for packet in packets:
    packet_info = {
        "timestamp": packet.time,
        "source_ip": packet[IP].src if IP in packet else None,
        "destination_ip": packet[IP].dst if IP in packet else None,
        "protocol": packet[IP].proto if IP in packet else None,
        "tcp_flags": packet.sprintf("%TCP.flags%") if TCP in packet else None,
        "payload_length": len(packet[TCP].payload) if TCP in packet else None,
        "dns_query": packet[DNSQR].qname if DNSQR in packet else None,
        "dns_response": packet[DNSRR].rdata if DNSRR in packet else None,
        "mac_source": packet.src,
        "mac_destination": packet.dst,
        "length": len(packet),
        'src_port': src_port,
        'dst_port': dst_port,
    }
    packets_data.append(packet_info)


cap.close # Close the PyShark capture

# Convert the lists of dictionaries to pandas dataframes
df_packets = pd.DataFrame(packets_data)
df_http = pd.DataFrame(http_data)

# Display the first few rows of each DataFrame
print("General Packet Data:")
print(df_packets.head())
print("\nHTTP-specific Data:")
print(df_http.head())


# Example of a simple merge based on an assumed common key
#combined_df = pd.merge(df_packets, df_http, on=['timestamp', 'source_ip', 'destination_ip', 'src_port', 'dst_port'], how='outer')

#combined_df.to_csv('combined_network_data.csv', index=False)
#

df_packets.to_csv('general_packet_data.csv', index=False)
df_http.to_csv('http_data.csv', index=False)


