from scapy.layers.inet import IP, TCP, UDP

def extract_features(packet):

    features = {}
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['proto'] = packet[IP].proto
        features['length'] = len(packet)

    if TCP in packet:
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport

    if UDP in packet:
        features['src_port'] = packet[UDP].sport
        features['dst_port'] = packet[UDP].dport

    return features
