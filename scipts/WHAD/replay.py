import logging
import time
import serial
from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4
from scapy.layers.zigbee import *

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)



class ZigbeePacketSender:
    def __init__(self, port='/dev/ttyACM0', baud_rate=115200):
        """
        Initialisation du port série pour l'envoi de paquets Zigbee
        
        Args:
            port (str): Port série pour la transmission
            baud_rate (int): Vitesse de transmission
        """
        self.channel = 13  # Canal Zigbee
        self.pan_id = 0x1900  # PAN ID spécifié
        self.broadcast_address = 0xFFFF  # Adresse de broadcast
        self.CompteurSeq = 0  # Compteur de séquence pour les paquets

        try:
            self.ser = serial.Serial(
                port=port, 
                baudrate=baud_rate, 
                timeout=1
            )
            logger.info(f"Port série {port} ouvert avec succès")
        except serial.SerialException as e:
            logger.error(f"Erreur d'ouverture du port série : {e}")
            raise

    def create_zigbee_packet(self, payload, 
                              dest_addr=0xFFFF, 
                              src_addr=0x9ABC, 
                              profile=0x0104):
        """
        Crée un paquet Zigbee personnalisé avec correction de la trame Dot15d4
        
        Args:
            payload (bytes): Charge utile à envoyer
            dest_addr (int): Adresse de destination
            src_addr (int): Adresse source
            profile (int): Profil Zigbee
        
        Returns:
            Scapy Packet: Paquet Zigbee construit
        """
        try:
            zigbee_packet = (
                Dot15d4(
                    fcf_frametype=1,  # Data frame
                    fcf_security=0,   # No security
                    fcf_ackreq=0,     # No ACK requested
                    fcf_pending=0,    # No pending frame
                    fcf_destaddrmode=2,  # Short destination address
                    fcf_srcaddrmode=2,   # Short source address
                    fcf_framever=0,   # Compatibility with 2003 version
                    seqnum=self.CompteurSeq  # Random sequence number
                ) /
                ZigbeeNWK(
                    frametype=0,  # Data frame
                    destination=dest_addr,
                    source=src_addr,
                    radius=30  # Nombre de sauts maximum
                ) /
                ZigbeeAppDataPayload(
                    aps_frametype=0,  # Data frame
                    delivery_mode=0,  # Unicast
                    dst_endpoint=0x01,
                    src_endpoint=0x01,
                    cluster=0x0006,  # Cluster On/Off
                    profile=profile,
                    counter=random.randint(0, 255)  # Random APS counter
                ) /
                ZigbeeClusterLibrary(
                    zcl_frametype=0x01,
                    command_direction=0,
                    transaction_sequence=random.randint(0, 255),
                    command_identifier=0x02  # Commande Toggle
                )
            )

            # Ajout de la charge utile personnalisée si fournie
            if payload:
                zigbee_packet = zigbee_packet / Raw(load=payload)
            if self.CompteurSeq == 255:
                self.CompteurSeq = 0
            else:
                self.CompteurSeq += 1
            return zigbee_packet

        except Exception as e:
            logger.error(f"Erreur de création du paquet : {e}")
            raise

    def send_zigbee_packet(self, payload):
        """
        Envoi d'un paquet Zigbee sur le canal spécifié
        
        Args:
            payload (bytes): Données à transmettre
        """
        try:
            # Création du paquet
            zigbee_packet = self.create_zigbee_packet(payload)
            
            # Conversion en octets
            packet_bytes = bytes(zigbee_packet)
            
            # Construction de la trame complète
            full_frame = bytearray([
                len(packet_bytes) + 3,  # Longueur de la trame
                self.channel,            # Numéro du canal
                self.pan_id >> 8,        # Octet de poids fort du PAN ID
                self.pan_id & 0xFF,      # Octet de poids faible du PAN ID
            ])
            full_frame.extend(packet_bytes)

            # Envoi du paquet
            self.ser.write(full_frame)
            
            logger.info(f"Paquet Zigbee envoyé :")
            logger.info(f" Canal : {self.channel}")
            logger.info(f" PAN ID : 0x{self.pan_id:04X}")
            logger.info(f" Adresse : Broadcast (0x{self.broadcast_address:04X})")
            logger.info(f" Taille : {len(payload)} octets")
            logger.info(f" Données : {payload}")
            logger.info(f"Compteur de Seq : {self.CompteurSeq}")

        except Exception as e:
            logger.error(f"Erreur d'envoi du paquet : {e}")
            # Ajout d'un diagnostic supplémentaire
            import traceback
            traceback.print_exc()

    def close(self):
        """Fermeture du port série"""
        if hasattr(self, 'ser') and self.ser.is_open:
            self.ser.close()
            logger.info("Port série fermé")

def main():
    """
    Fonction principale pour l'envoi de paquets Zigbee
    """
    try:
        # Initialisation de l'envoyeur de paquets
        sender = ZigbeePacketSender()

        # Envoi des paquets
        messages = [
            b'Commande Toggle',
            b'Test de transmission Zigbee',
            b'Paquet de demonstration'
        ]

        # Envoi de messages multiples
        while True:
            sender.send_zigbee_packet(messages[0])
            time.sleep(1)  # Délai entre les transmissions

    except Exception as e:
        logger.error(f"Erreur lors de l'exécution : {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Assurez-vous de fermer le port série
        if 'sender' in locals():
            sender.close()

if __name__ == "__main__":
    main()