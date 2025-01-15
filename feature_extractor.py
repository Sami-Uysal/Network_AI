from scapy.layers.inet import IP, TCP, UDP

def extract_features(packet):
    features = {
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "proto": 0,
        "sbytes": 0,
        "dbytes": 0,
        "dur": 0
    }
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['proto'] = packet[IP].proto
        features['sbytes'] = len(packet[IP].payload)
        features['dbytes'] = len(packet[IP].payload)

    if TCP in packet or UDP in packet:
        protocol = TCP if TCP in packet else UDP
        features['src_port'] = packet[protocol].sport
        features['dst_port'] = packet[protocol].dport

    return features
