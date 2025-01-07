from scapy.layers.inet import IP, TCP, UDP

def extract_features(packet):

    features = {}
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['proto'] = packet[IP].proto
        features['length'] = len(packet)

    if TCP in packet or UDP in packet:
        transport_layer = TCP if TCP in packet else UDP
        features['src_port'] = packet[transport_layer].sport
        features['dst_port'] = packet[transport_layer].dport

    return features
