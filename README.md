from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def process_packet(packet):
    print("\n🔹 Packet Captured")

    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"🌐 IP: {ip.src} -> {ip.dst}")
        print(f"📦 Protocol: {ip.proto}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"🔁 TCP: {tcp.sport} -> {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"📨 UDP: {udp.sport} -> {udp.dport}")

        elif packet.haslayer(ICMP):
            print("📢 ICMP Packet")

# Start sniffing (default interface)
print("🚦 Starting packet sniffing... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)
