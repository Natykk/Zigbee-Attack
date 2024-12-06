from scapy.all import rdpcap
from whad.device import WhadDevice
from whad.zigbee import Sniffer

# Clé par défaut de l'ESP32-H2 pour le décryptage ZigBee (par exemple)
DEFAULT_KEY = b"00112233445566778899AABBCCDDEEFF"  # Remplacez cela par la clé réelle de votre ESP32-H2

# Créer l'objet WhadDevice (même si nous n'utilisons pas de périphérique physique)
device = WhadDevice.create("uart0")

# Créer l'instance du sniffer ZigBee
sniffer = Sniffer(device)

# Ajouter la clé de chiffrement par défaut de l'ESP32-H2
sniffer.add_key(DEFAULT_KEY)

# Définir le canal et activer le décryptage
sniffer.channel = 13
sniffer.decrypt = True

# Fonction pour traiter un fichier pcap
def process_pcap(pcap_file):
    # Lire le fichier pcap avec Scapy
    packets = rdpcap(pcap_file)
    print(f"[i] Ouverture du fichier pcap '{pcap_file}' avec {len(packets)} paquets.")
    
    # Traiter chaque paquet du fichier pcap
    for packet in packets:
        # Traiter le paquet avec le sniffer
        processed_packet = sniffer.process_packet(packet)
        
        if processed_packet:
            print(f"[i] Paquet traité : {processed_packet.summary()}")  # Résumé du paquet

            # Extraire des informations détaillées du ZigBee Security Header
            try:
                couche_802_15_4 = processed_packet[0]  # Extraire la couche 802.15.4
                print("[i] Couche 802.15.4:")
                #couche_802_15_4.show()  # Afficher la couche 802.15.4
            except IndexError:
                print("[!] 802.15.4 inexistant")

            try:
                couche_zigbee = processed_packet[1]  # Extraire la couche ZigBee
                print("[i] Couche ZigBee:")
                #couche_zigbee.show()  # Afficher la couche ZigBee
            except IndexError:
                print("[!] ZigBee inexistant")
            
        else:
            print("[!] Paquet non traité.")
        
        print("=========================================================================")

# Ouvrir et traiter le fichier pcap
process_pcap("../Wireshark/light_switch.pcapng")

# Fermer le périphérique (bien que nous ne l'utilisions pas ici)
device.close()
