import logging
import pyshark

# Configuration du journal (logging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def traiter_paquet(paquet, numero_paquet):
    """
    Traite un paquet ZigBee individuel et affiche les détails pertinents, 
    y compris les clés, compteurs, étiquettes de clés et clusters.

    Args:
        paquet: Paquet Pyshark à traiter.
        numero_paquet (int): Numéro du paquet pour les besoins de journalisation.
    """
    try:
        logger.info(f"Traitement du paquet {numero_paquet}...")

        # Couche WPAN (802.15.4)
        if hasattr(paquet, 'wpan'):
            print("\n *** Couche WPAN (802.15.4) ***")
            #print(paquet.wpan)
            if hasattr(paquet.wpan, 'wpan_frame_counter'):
                print(f"Compteur de trame : {paquet.wpan.wpan_frame_counter}")

        # Couche NWK ZigBee
        if hasattr(paquet, 'zbee_nwk'):
            print("\n *** Couche NWK ***")
            #print(paquet.zbee_nwk)
            if hasattr(paquet.zbee_nwk, 'zbee_nwk_key_seqno'):
                print(f"Numéro de séquence de clé : {paquet.zbee_nwk.zbee_nwk_key_seqno}")
            if hasattr(paquet.zbee_nwk, 'zbee_nwk_frame_counter'):
                print(f"Compteur de trame NWK : {paquet.zbee_nwk.zbee_nwk_frame_counter}")

        # Couche APS ZigBee
        if hasattr(paquet, 'zbee_aps'):
            print("\n *** Couche APS ***")
            #print(paquet.zbee_aps)
            if hasattr(paquet.zbee_aps, 'zbee_aps_key_label'):
                print(f"Étiquette de clé : {paquet.zbee_aps.zbee_aps_key_label}")
            if hasattr(paquet.zbee_aps, 'zbee_aps_frame_counter'):
                print(f"Compteur de trame APS : {paquet.zbee_aps.zbee_aps_frame_counter}")

        # Couche ZCL ZigBee
        if hasattr(paquet, 'zbee_zcl'):
            print("\n *** Couche ZCL ***")
            #print(paquet.zbee_zcl)
            if hasattr(paquet.zbee_zcl, 'zbee_zcl_cluster_id'):
                cluster_id = paquet.zbee_zcl.zbee_zcl_cluster_id
                print(f"ID du cluster : {cluster_id}")
                if cluster_id == "0x0006":  # Cluster On/Off
                    print("Cluster : On/Off")
                elif cluster_id == "0x0008":  # Cluster Level Control
                    print("Cluster : Level Control")

    except Exception as e:
        logger.error(f"Erreur lors du traitement du paquet {numero_paquet} : {e}")

def traiter_pcap(fichier_pcap):
    """
    Traite un fichier PCAP ZigBee et affiche les détails de chaque paquet.

    Args:
        fichier_pcap (str): Chemin vers le fichier PCAP à traiter.
    """
    try:
        capture = pyshark.FileCapture(fichier_pcap, display_filter="wpan")
        logger.info(f"Fichier PCAP ouvert : '{fichier_pcap}'")

        for idx, paquet in enumerate(capture, 1):
            traiter_paquet(paquet, idx)

    except FileNotFoundError:
        logger.error(f"Fichier PCAP non trouvé : {fichier_pcap}")
    except Exception as e:
        logger.error(f"Erreur inattendue lors du traitement du fichier PCAP : {e}")

def main():
    """
    Fonction principale pour démontrer le traitement de fichiers PCAP ZigBee.
    """
    fichier_pcap = "../Wireshark/light_switch.pcapng"  # Remplacez par le chemin réel de votre fichier
    traiter_pcap(fichier_pcap)

if __name__ == "__main__":
    main()
