from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap
from scapy.layers.l2 import Ether  # Import Ethernet layer
from scapy.layers.inet import IP # Import IP layers to detect EtherType
from scapy.all import*

try:
    # Read input PCAP file
    FileInp = rdpcap('srsran_gtpu_example.pcap')
except Exception as e:
    print(f"Error reading PCAP file: {e}")
    FileInp = []

# Output PCAP file name
output_pcap = "Extracted_payload_with_dynamic_ethernet.pcap"

# List to hold modified packets
modified_packets = []

def ip_to_mac(ip: str) -> str:
    """Generate a pseudo-MAC address from an IP address for testing."""
    octets = ip.split('.')
    if len(octets) == 4:  # IPv4
        mac = "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            int(octets[0]), int(octets[1]), int(octets[2]), int(octets[3]), 0
        )
    else:  # Fallback for non-IPv4
        mac = "02:00:00:00:00:00"
    return mac

for packet in FileInp:
    # Check if packet contains a Raw layer
    if Raw in packet:
        # Extract raw payload
        raw_data = bytes(packet[Raw])
        
        # Assume GTP-U header is 16 bytes, extract payload after header
        payload_data = raw_data[16:]
        
        # Detect EtherType and extract source/destination IPs
        first_nibble = payload_data[0] >> 4
        if first_nibble == 4:  # IPv4
            ethertype = 0x0800
            ip_packet = IP(payload_data)
            src_ip = ip_packet.src
            dst_ip = ip_packet.dst
        elif first_nibble == 6:  # IPv6
            ethertype = 0x86DD
            ip_packet = IPv6(payload_data)
            src_ip = ip_packet.src
            dst_ip = ip_packet.dst
        else:
            print(f"Unknown payload type, skipping packet: {first_nibble}")
            continue
        
        # Generate MAC addresses based on IPs
        src_mac = ip_to_mac(src_ip)
        dst_mac = ip_to_mac(dst_ip)
        
        # Create an Ethernet header with dynamic MACs
        eth_header = Ether(
            src=src_mac,
            dst=dst_mac,
            type=ethertype  # EtherType based on payload
        )
        
        # Recreate the packet with the Ethernet header and payload
        modified_packet = eth_header / payload_data
        modified_packet.time= packet.time
        # Append the modified packet to the list
        modified_packets.append(modified_packet)

# Write all modified packets to a new PCAP file
if modified_packets:
    wrpcap(output_pcap, modified_packets)
    print(f"Extracted packets with dynamic Ethernet headers written to {output_pcap}")
else:
    print("No packets with Raw payloads found.")
