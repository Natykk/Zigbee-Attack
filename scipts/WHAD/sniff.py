from whad.zigbee import Sniffer

# Initialiser le sniffer
sniffer = Sniffer(device)
sniffer.channel = 11  # Canal Zigbee
sniffer.decrypt = True  # Activer le décryptage (si les clés sont récupérables)

# Capture des paquets
captured_packets = []
for packet in sniffer.sniff(timeout=10):  # Sniff pendant 10 secondes
    captured_packets.append(packet)
    packet.show()  # Afficher les détails des paquets capturés

