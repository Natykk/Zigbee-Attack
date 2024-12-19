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

# Fonctions utilitaires
def trouver_peripheriques_serie():
    return glob.glob('/dev/ttyACM*')

def calculer_entropie(donnees):
    if not donnees:
        return 0.0
    comptage = {octet: donnees.count(octet) for octet in set(donnees)}
    total = len(donnees)
    return -sum((c / total) * math.log2(c / total) for c in comptage.values())

def decrypter_payload_zigbee(payload_hex, cle_hex):
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
    def __init__(self, canal=13, fichier_sortie='captures_zigbee.json', vitesse_bauds=115200):
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
        peripheriques = trouver_peripheriques_serie()
        if not peripheriques:
            raise RuntimeError("Aucun périphérique série USB trouvé")
        logger.info(f"Périphériques disponibles : {peripheriques}")
        return peripheriques[0]

    def _configurer_sniffer(self):
        try:
            self.port_serie = serial.Serial(self.interface, baudrate=self.vitesse_bauds, timeout=1)
            logger.info(f"Configuration du sniffer sur {self.interface}")
        except serial.SerialException as e:
            logger.error(f"Erreur de configuration du sniffer : {e}")
            self._fermer_port_serie()
            raise

    def _fermer_port_serie(self):
        if self.port_serie and self.port_serie.is_open:
            self.port_serie.close()

    def _capturer_paquets(self):
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
        while self.est_en_cours:
            try:
                # Lire un paquet depuis la file d'attente
                paquet = self.file_paquets.get(timeout=1)
                #paquet = "received: 6188300019146e0000481a146e00001e222f3c60feffbd4d749e2860feffbd4d7428247002009e2860feffbd4d74005ca080848585055c298eab1c1c9f41 power: -57 lqi: 148 time: 7763236444"
                # Convertir le paquet en format hexadécimal et le décoder
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
                    
                    # Décoder la trame Zigbee complète
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
        try:
            self.est_en_cours = True
            self._configurer_sniffer()
            threading.Thread(target=self._capturer_paquets, daemon=True).start()
            threading.Thread(target=self._traiter_paquets, daemon=True).start()
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du sniffer : {e}")

    def arreter_sniffer(self):
        self.est_en_cours = False
        logger.info("Arrêt du sniffer")

    def sauvegarder_captures(self):
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