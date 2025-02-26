"""
Module : sniffeur_zigbee
=========================

Ce module implémente un sniffeur de trames Zigbee.

Il fournit les fonctionnalités pour capturer, décoder et analyser les trames Zigbee
depuis une interface série, ainsi que pour sauvegarder les captures dans un fichier JSON.
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

    Cette fonction explore le système pour trouver tous les périphériques dont
    le nom correspond au motif '/dev/tty*', ce qui est généralement le cas sur
    les systèmes Unix/Linux pour les interfaces série.

    Retours
    -------
    list
        Liste des chemins d'accès aux périphériques série trouvés.
    """
    return glob.glob('/dev/tty*')


class SniffeurZigbee:
    """
    Classe pour capturer et analyser les trames ZigBee.

    Cette classe gère la capture des trames ZigBee via un port série, leur décodage 
    grâce à un décodeur spécialisé, ainsi que leur sauvegarde dans un fichier JSON.
    Elle peut également être étendue pour prendre en charge le déchiffrement des trames.

    Paramètres
    ----------
    canal : int, optionnel
        Canal ZigBee sur lequel écouter (par défaut 13).
    fichier_sortie : str, optionnel
        Chemin du fichier de sortie pour sauvegarder les captures 
        (par défaut 'captures_zigbee.json').
    vitesse_bauds : int, optionnel
        Vitesse de transmission du port série (par défaut 115200).

    Attributs
    ----------
    canal : int
        Canal ZigBee sélectionné.
    fichier_sortie : str
        Chemin vers le fichier de sortie.
    vitesse_bauds : int
        Vitesse de transmission en bauds.
    file_paquets : Queue
        File d'attente utilisée pour stocker les paquets bruts capturés.
    est_en_cours : bool
        Indique si le sniffer est en cours d'exécution.
    port_serie : serial.Serial
        Instance du port série configuré pour la capture.
    interface : str
        Nom du périphérique série sélectionné.
    captures : list
        Liste des trames ZigBee décodées et leurs métadonnées associées.
    cle_dechiffrement : str
        Clé utilisée pour le déchiffrement des trames, si nécessaire.
    metadonnees : list
        Liste des métadonnées associées aux captures.
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
        """
        Réinitialise complètement l'état du sniffer.

        Cette méthode vide la liste des captures, la file d'attente des paquets
        ainsi que les métadonnées accumulées. Si le port série est ouvert, elle 
        réinitialise également ses buffers d'entrée et de sortie.
        """
        self.captures.clear()
        self.file_paquets.queue.clear()
        self.metadonnees.clear()
        
        try:
            if self.port_serie and self.port_serie.is_open:
                self.port_serie.reset_input_buffer()  
                self.port_serie.reset_output_buffer()
                with self.file_paquets.mutex:
                    self.file_paquets.queue.clear()
                self.captures.clear()
        except Exception as e:
            logger.error(f"Erreur lors de la réinitialisation du sniffer : {e}")

    def _selectionner_interface(self):
        """
        Sélectionne le périphérique série disponible pour le sniffer.

        Cette méthode recherche tous les périphériques série disponibles et
        retourne celui par défaut. Ici, le périphérique '/dev/ttyACM0' est utilisé,
        mais cette méthode peut être adaptée pour sélectionner dynamiquement.

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
        return '/dev/ttyACM0'  # Ou peripheriques[0] pour utiliser le premier trouvé

    def _configurer_sniffer(self):
        """
        Configure le sniffer pour la capture des trames ZigBee via le port série.

        Cette méthode initialise l'objet serial.Serial avec les paramètres 
        appropriés et réinitialise les buffers d'entrée et de sortie.

        Lève
        ----
        RuntimeError
            En cas d'échec de la configuration du port série.
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

        Cette méthode vérifie si le port série est actif et le ferme proprement.
        """
        if self.port_serie and self.port_serie.is_open:
            self.port_serie.close()

    def _capturer_paquets(self):
        """
        Capture les paquets depuis le port série et les ajoute à la file d'attente.

        Cette méthode s'exécute dans un thread séparé et lit en continu depuis le
        port série. Chaque ligne reçue est décodée en UTF-8, épurée des espaces inutiles,
        et placée dans la file d'attente pour traitement ultérieur.

        En cas d'erreur de port série, un message d'erreur est logué.
        """
        try:
            logger.info(f"Début de capture sur {self.interface}, canal {self.canal}")
            # Vider les buffers avant de démarrer
            self.port_serie.reset_input_buffer()
            self.port_serie.reset_output_buffer()
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
        Traite les paquets capturés en les décodant et en les stockant dans la liste des captures.

        Pour chaque paquet récupéré dans la file d'attente, cette méthode :
            - Extrait la partie correspondant à la trame en hexadécimal.
            - Convertit la chaîne hexadécimale en bytes.
            - Utilise l'instance de DecodeurTrameZigbee pour décoder la trame.
            - Ajoute des métadonnées (puissance, LQI, timestamp) extraites du paquet.
            - Stocke la trame décodée avec ses métadonnées dans la liste des captures.

        Paramètres
        ----------
        decoder : DecodeurTrameZigbee, optionnel
            Instance du décodeur de trames ZigBee à utiliser (par défaut une instance de DecodeurTrameZigbee).
        """
        while self.est_en_cours:
            try:
                paquet = self.file_paquets.get(timeout=1)
                try:
                    # On suppose que le paquet est constitué de plusieurs champs séparés par des espaces.
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
        Démarre le sniffer pour capturer les trames ZigBee.

        Cette méthode configure le port série puis lance deux threads en mode daemon :
            - Un thread pour la capture des paquets (_capturer_paquets).
            - Un thread pour le traitement et le décodage des paquets (_traiter_paquets).

        En cas d'erreur lors du démarrage, un message d'erreur est logué.
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

        Cette méthode modifie le drapeau d'exécution afin d'arrêter les threads de capture 
        et de traitement. Un message d'information est logué pour indiquer l'arrêt.
        """
        self.est_en_cours = False
        logger.info("Arrêt du sniffer")

    def sauvegarder_captures(self):
        """
        Sauvegarde les trames capturées dans un fichier JSON.

        Les captures présentes dans la liste self.captures sont écrites dans le fichier
        spécifié par l'attribut fichier_sortie avec une indentation pour une lecture facilitée.

        Lève
        ----
        Exception
            Si une erreur survient lors de l'écriture dans le fichier.
        """
        try:
            with open(self.fichier_sortie, 'w', encoding='utf-8') as f:
                json.dump(self.captures, f, indent=2, ensure_ascii=False)
            logger.info(f"Captures sauvegardées dans {self.fichier_sortie}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des captures : {e}")
