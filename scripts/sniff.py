"""
Ce Module implémente un sniffeur de trames Zigbee.
"""
import serial
import logging
import threading
import queue
import time
import json
import glob
from datetime import datetime
from Crypto.Cipher import AES
import math
from DecodeurTrame import DecodeurTrameZigbee

# Configuration de la journalisation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s : %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sniffeur_zigbee.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

def trouver_peripheriques_serie():
    """
    @brief Recherche des périphériques série USB compatibles.
    
    @return: Liste des périphériques série trouvés.
    @rtype: list
    """
    return glob.glob('/dev/ttyACM*')

def calculer_entropie(donnees):
    """
    @brief Calcule l'entropie d'un jeu de données.
    
    @param donnees: Données pour lesquelles l'entropie est calculée, sous forme de bytes.
    @type donnees: bytes
    
    @return: Entropie des données.
    @rtype: float
    """
    if not donnees:
        return 0.0
    comptage = {octet: donnees.count(octet) for octet in set(donnees)}
    total = len(donnees)
    return -sum((c / total) * math.log2(c / total) for c in comptage.values())

def decrypter_payload_zigbee(payload_hex, cle_hex):
    """
    @brief Décrypte un payload Zigbee chiffré avec AES en mode CCM.
    
    @param payload_hex: Payload chiffré en hexadécimal.
    @type payload_hex: str
    @param cle_hex: Clé de chiffrement en hexadécimal.
    @type cle_hex: str
    
    @return: Dictionnaire contenant le résultat du décryptage.
    @rtype: dict
    """
    try:
        payload = bytes.fromhex(payload_hex)
        cle = bytes.fromhex(cle_hex)

        nonce = payload[:13]
        tag = payload[-4:]
        donnees_chiffrees = payload[13:-4]

        cipher = AES.new(cle, AES.MODE_CCM, nonce=nonce, mac_len=4)
        payload_dechiffre = cipher.decrypt_and_verify(donnees_chiffrees, tag)
        return {
            'succes': True,
            'nonce': nonce.hex(),
            'tag': tag.hex(),
            'payload_dechiffre': payload_dechiffre.decode('utf-8', errors='ignore')
        }
    except ValueError as e:
        return {'succes': False, 'erreur': f"Erreur de vérification du MAC : {str(e)}"}
    except Exception as e:
        return {'succes': False, 'erreur': f"Erreur de déchiffrement : {str(e)}"}

class SniffeurZigbee:
    """
    @class SniffeurZigbee
    @brief Classe pour capturer et analyser les trames ZigBee.
    @details Cette classe gère la capture des trames ZigBee depuis un périphérique série, les décodent et les sauvegardent dans un fichier JSON.
    Elle prend également en charge le décryptage des trames lorsque nécessaire.
    """

    def __init__(self, canal=13, fichier_sortie='captures_zigbee.json', vitesse_bauds=115200):
        """
        @brief Constructeur de la classe SniffeurZigbee.
        
        @param canal: Canal ZigBee sur lequel écouter. Valeur par défaut : 13.
        @type canal: int
        @param fichier_sortie: Nom du fichier de sortie pour les captures. Valeur par défaut : 'captures_zigbee.json'.
        @type fichier_sortie: str
        @param vitesse_bauds: Vitesse de transmission série. Valeur par défaut : 115200.
        @type vitesse_bauds: int
        """
        self.canal = canal
        self.fichier_sortie = fichier_sortie
        self.vitesse_bauds = vitesse_bauds
        self.file_paquets = queue.Queue(maxsize=1000)
        self.est_en_cours = False
        self.port_serie = None
        self.interface = self._selectionner_interface()
        self.captures = []
        self.cle_dechiffrement = "9b9494920170aeed67e90ce7d672face"
        self.metadonnees = []

    def _selectionner_interface(self):
        """
        @brief Sélectionne le périphérique série disponible pour le sniffer.
        
        @return: Nom du périphérique série sélectionné.
        @rtype: str
        
        @raise RuntimeError: Si aucun périphérique série n'est trouvé.
        """
        peripheriques = trouver_peripheriques_erie()
        if not peripheriques:
            raise RuntimeError("Aucun périphérique série USB trouvé")
        logger.info(f"Périphériques disponibles : {peripheriques}")
        return peripheriques[0]

    def _configurer_sniffer(self):
        """
        @brief Configure le sniffer pour capturer les trames ZigBee via un port série.
        
        @raise RuntimeError: Si la configuration échoue.
        """
        try:
            self.port_serie = serial.Serial(self.interface, baudrate=self.vitesse_bauds, timeout=1)
            logger.info(f"Configuration du sniffer sur {self.interface}")
        except serial.SerialException as e:
            logger.error(f"Erreur de configuration du sniffer : {e}")
            self._fermer_port_serie()
            raise

    def _fermer_port_serie(self):
        """
        @brief Ferme le port série s'il est ouvert.
        """
        if self.port_serie and self.port_serie.is_open:
            self.port_serie.close()

    def _capturer_paquets(self):
        """
        @brief Capture les paquets depuis le port série et les ajoute à la file d'attente.
        """
        try:
            logger.info(f"Début de capture sur {self.interface}, canal {self.canal}")
            while self.est_en_cours:
                if self.port_serie.in_waiting:
                    donnees_brutes = self.port_serie.readline().decode('utf-8').strip()
                    if donnees_brutes:
                        try:
                            self.file_paquets.put_nowait(donnees_brutes)
                        except queue.Full:
                            logger.warning("File de paquets pleine, paquet ignoré.")
        except serial.SerialException as e:
            logger.error(f"Erreur de port série : {e}")
        finally:
            self._fermer_port_serie()

    def _traiter_paquets(self, decoder=DecodeurTrameZigbee()):
        """
        @brief Traite les paquets capturés, les décode et les ajoute à la liste des captures.
        
        @param decoder: Instance de la classe DecodeurTrameZigbee utilisée pour décoder les trames.
        @type decoder: DecodeurTrameZigbee
        """
        while self.est_en_cours:
            try:
                paquet = self.file_paquets.get(timeout=1)
                try:
                    logger.info(f"Paquet brut reçu : {paquet}")
                    paquet_received = paquet.split(" ")[1]  # Extraction des données reçues
                    paquet_bytes = bytes.fromhex(paquet_received)  # Conversion hex->bytes

                    # Extraction des métadonnées depuis la chaîne de paquet
                    metadonnees = {
                        'power': paquet.split(" ")[3],  # Valeur de power
                        'lqi': paquet.split(" ")[5],    # Valeur de lqi
                        'timestamp': paquet.split(" ")[7]  # Valeur du timestamp
                    }
                    
                    decoded_frame = decoder.decoder_trame_zigbee(paquet_bytes)
                    if decoded_frame:
                        logger.info(f"Trame Zigbee décodée : {decoded_frame}")
                        decoded_frame['metadonnees'] = metadonnees
                        self.captures.append(decoded_frame)
                        
                    else:
                        logger.warning(f"Impossible de décoder la trame : {paquet_received}")
                except Exception as e:
                    logger.error(f"Erreur lors du traitement du paquet : {e}")
            except queue.Empty:
                pass

    def demarrer_sniffer(self):
        """
        @brief Démarre le sniffer pour commencer à capturer les trames ZigBee.
        
        Cette méthode démarre deux threads : un pour capturer les paquets et un autre pour les traiter.
        """
        try:
            self.est_en_cours = True
            self._configurer_sniffer()
            threading.Thread(target=self._capturer_paquets, daemon=True).start()
            threading.Thread(target=self._traiter_paquets, daemon=True).start()
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du sniffer : {e}")

    def arreter_sniffer(self):
        """
        @brief Arrête le sniffer.
        """
        self.est_en_cours = False
        logger.info("Arrêt du sniffer")

    def sauvegarder_captures(self):
        """
        @brief Sauvegarde les captures dans un fichier JSON.
        
        Cette méthode écrit les captures dans un fichier spécifié lors de l'initialisation de la classe.
        """
        try:
            with open(self.fichier_sortie, 'w', encoding='utf-8') as f:
                json.dump(self.captures, f, indent=2, ensure_ascii=False)
            logger.info(f"Captures sauvegardées dans {self.fichier_sortie}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des captures : {e}")

'''
# Exemple d'utilisation
if __name__ == "__main__":
    sniffer = SniffeurZigbee()
    sniffer.demarrer_sniffer()
    time.sleep(10)  # Capture pendant 10 secondes
    sniffer.arreter_sniffer()
    sniffer.sauvegarder_captures()
'''