from scapy.all import rdpcap, wrpcap

def load_pcap(file_path):
    return rdpcap(file_path)

def save_pcap(packets, file_path):
    wrpcap(file_path, packets)