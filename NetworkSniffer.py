# Basic Network Sniffer using Scapy
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Callback function to process each captured packet
def packet_callback(packet):
    print("\n==============================")

    # Check if packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")

        # TCP Packet
        if TCP in packet:
            tcp_layer = packet[TCP]
            print("Protocol       : TCP")
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload        : {bytes(tcp_layer.payload)}")

        # UDP Packet
        elif UDP in packet:
            udp_layer = packet[UDP]
            print("Protocol       : UDP")
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload        : {bytes(udp_layer.payload)}")

        # ICMP Packet
        elif ICMP in packet:
            print("Protocol       : ICMP")

    # Non-IP Packet
    else:
        print("Non-IP Packet Detected")

    # Print raw packet data
def main():
    print("🚀 Starting Basic Network Sniffer...")
    print("Press CTRL+C to stop\n")

    #  Start sniffing packets
    sniff(prn=packet_callback, store=False)

    # Print raw packet data
if __name__ == "__main__":
    main()