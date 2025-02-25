"""
Module implémentant un sniffeur de trames Zigbee.

Ce module fournit les fonctionnalités pour capturer et analyser les trames Zigbee
depuis une interface série.
"""
import serial
import logging
import threading
import queue
import time
import json
import glob
from datetime import datetime
from Cryptodome.Cipher import AES
import math
from DecodeurTrame import DecodeurTrameZigbee
#from Cryptodome.Util.Padding import pad,Counter

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
    Recherche les périphériques série USB compatibles.

    Retours
    -------
    list
        Liste des périphériques série trouvés.
    """
    return glob.glob('/dev/ttyACM*')

class SniffeurZigbee:
    """
    Classe pour capturer et analyser les trames ZigBee.

    Cette classe gère la capture des trames ZigBee depuis un périphérique série,
    leur décodage et leur sauvegarde dans un fichier JSON. Elle prend également
    en charge le déchiffrement des trames lorsque nécessaire.

    Paramètres
    ----------
    canal : int, optionnel
        Canal ZigBee sur lequel écouter (par défaut 13)
    fichier_sortie : str, optionnel
        Nom du fichier de sortie pour les captures (par défaut 'captures_zigbee.json')
    vitesse_bauds : int, optionnel
        Vitesse de transmission série (par défaut 115200)

    Attributs
    ----------
    canal : int
        Canal ZigBee sélectionné
    fichier_sortie : str
        Chemin vers le fichier de sortie
    vitesse_bauds : int
        Vitesse de transmission en bauds
    file_paquets : Queue
        File d'attente pour stocker les paquets capturés
    est_en_cours : bool
        Drapeau indiquant si la capture est active
    port_serie : serial.Serial
        Objet port série
    interface : str
        Interface série sélectionnée
    captures : list
        Liste des trames capturées
    cle_dechiffrement : str
        Clé de déchiffrement
    metadonnees : list
        Liste des métadonnées de capture
    """

    def __init__(self, canal=13, fichier_sortie='captures_zigbee.json', vitesse_bauds=115200):
        self.canal = canal
        self.fichier_sortie = fichier_sortie
        self.vitesse_bauds = vitesse_bauds
        self.file_paquets = queue.Queue(maxsize=1000)
        self.est_en_cours = False
        self.port_serie = None
        self.interface = self._selectionner_interface()
        self.captures = []
        self.cle_dechiffrement = ""
        self.metadonnees = []


    def reinitialiser(self):
        """Réinitialise complètement l'état du sniffer"""
        self.captures.clear()
        self.file_paquets.queue.clear()
        self.metadonnees.clear()
        
        if self.port_serie and self.port_serie.is_open:
            self.port_serie.reset_input_buffer()  
            self.port_serie.reset_output_buffer()

    def _selectionner_interface(self):
        """
        Sélectionne le périphérique série disponible pour le sniffer.

        Retours
        -------
        str
            Nom du périphérique série sélectionné.

        Lève
        ----
        RuntimeError
            Si aucun périphérique série n'est trouvé.
        """
        peripheriques = trouver_peripheriques_serie()
        if not peripheriques:
            raise RuntimeError("Aucun périphérique série USB trouvé")
        logger.info(f"Périphériques disponibles : {peripheriques}")
        return '/dev/ttyACM0' #peripheriques[0]

    def _configurer_sniffer(self):
        """
        Configure le sniffer pour capturer les trames ZigBee via le port série.

        Lève
        ----
        RuntimeError
            Si la configuration échoue.
        """
        try:
            self.port_serie = serial.Serial(self.interface, baudrate=self.vitesse_bauds, timeout=1)
            self.port_serie.reset_input_buffer()
            logger.info(f"Configuration du sniffer sur {self.interface}")
        except serial.SerialException as e:
            logger.error(f"Erreur de configuration du sniffer : {e}")
            self._fermer_port_serie()
            raise

    def _fermer_port_serie(self):
        """
        Ferme le port série s'il est ouvert.
        """
        if self.port_serie and self.port_serie.is_open:
            self.port_serie.close()

    def _capturer_paquets(self):
        """
        Capture les paquets depuis le port série et les ajoute à la file d'attente.

        Cette méthode s'exécute dans un thread séparé et lit en continu depuis le
        port série, ajoutant les paquets reçus à la file d'attente.
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
        Traite les paquets capturés, les décode et les ajoute à la liste des captures.

        Paramètres
        ----------
        decoder : DecodeurTrameZigbee, optionnel
            Instance de la classe de décodage des trames ZigBee (par défaut DecodeurTrameZigbee())
        """
        while self.est_en_cours:
            try:
                paquet = self.file_paquets.get(timeout=1)
                try:
                    #logger.info(f"Paquet brut reçu : {paquet}")
                    paquet_received = paquet.split(" ")[1]
                    paquet_bytes = bytes.fromhex(paquet_received)
                    
                    metadonnees = {
                        'power': paquet.split(" ")[3],
                        'lqi': paquet.split(" ")[5],
                        'timestamp': paquet.split(" ")[7],
                        'trame_brute': paquet_received
                    }
                    
                    decoded_frame = decoder.decoder_trame_zigbee(paquet_bytes)
                    if decoded_frame:
                        #logger.info(f"Trame Zigbee décodée : {decoded_frame}")
                        
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
        Démarre le sniffer pour commencer à capturer les trames ZigBee.

        Cette méthode démarre deux threads : un pour la capture des paquets
        et un autre pour leur traitement.
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
        Arrête le sniffer.

        Cette méthode met le drapeau d'exécution à False, ce qui provoquera
        l'arrêt des threads de capture et de traitement.
        """
        self.est_en_cours = False
        logger.info("Arrêt du sniffer")

    def sauvegarder_captures(self):
        """
        Sauvegarde les captures dans un fichier JSON.

        Cette méthode écrit les captures dans le fichier spécifié lors de
        l'initialisation de la classe.

        Lève
        ----
        Exception
            Si une erreur survient lors de la sauvegarde des captures.
        """
        try:
            with open(self.fichier_sortie, 'w', encoding='utf-8') as f:
                json.dump(self.captures, f, indent=2, ensure_ascii=False)
            logger.info(f"Captures sauvegardées dans {self.fichier_sortie}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des captures : {e}")