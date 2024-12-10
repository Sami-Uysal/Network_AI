from scapy.all import sniff
from feature_extractor import extract_features
import json

def save_packet(packet):
    features = extract_features(packet)
    with open("packets.json", "a") as f:
        f.write(json.dumps(features) + "\n")

sniff(filter="ip", prn=save_packet, count=100)
