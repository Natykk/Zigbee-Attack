"""
Module : sniffeur_zigbee
=========================

Ce module implémente un sniffeur de trames Zigbee.

Il fournit les fonctionnalités pour capturer, décoder et analyser les trames Zigbee
depuis une interface série, ainsi que pour sauvegarder les captures dans un fichier JSON
ou PCAP.
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
import os
from DecodeurTrame import DecodeurTrameZigbee
# Import pour gestion PCAP
import scapy.all as scapy
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from scapy.config import conf
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

# Configuration spécifique pour Scapy - définir le protocole Zigbee
conf.dot15d4_protocol = "zigbee"

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
    grâce à un décodeur spécialisé, ainsi que leur sauvegarde dans un fichier JSON ou PCAP.
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
    format_sortie : str, optionnel
        Format du fichier de sortie ('json' ou 'pcap', par défaut 'json').

    Attributs
    ----------
    canal : int
        Canal ZigBee sélectionné.
    fichier_sortie : str
        Chemin vers le fichier de sortie.
    vitesse_bauds : int
        Vitesse de transmission en bauds.
    format_sortie : str
        Format du fichier de sortie choisi ('json' ou 'pcap').
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

    def __init__(self, canal=13, fichier_sortie='captures_zigbee.json', vitesse_bauds=115200, format_sortie='json',materiel='nrf52'):
        self.canal = canal
        self.fichier_sortie = fichier_sortie
        self.vitesse_bauds = vitesse_bauds
        self.format_sortie = format_sortie
        self.file_paquets = queue.Queue(maxsize=1000)
        self.est_en_cours = False
        self.port_serie = None
        self.interface = self._selectionner_interface()
        self.captures = []
        self.cle_dechiffrement = ""
        self.metadonnees = []
        self.pcap_writer = None
        self.materiel = materiel

    def definir_materiel(self, materiel):
        """
    Définit le materiel utilisé pour les trames capturées à partir du port série.
    
    Cette méthode permet de spécifier le format dans lequel les trames sont envoyées
    par le périphérique de capture (firmware). L'implémentation supporte deux formats :
    'nrf52' pour les trames provenant du nRF52840 et 'esp32h2' pour les trames
    provenant de l'ESP32H2.
    
    Paramètres
    ----------
    format_entree : str
        Format d'entrée à utiliser. Valeurs acceptées:
        - 'nrf52': Format de trame du nRF52840 avec la syntaxe "received: [trame_hex] power: [rssi] lqi: [lqi] time: [timestamp]"
        - 'esp32h2': Format de trame de l'ESP32H2 avec la syntaxe "[ sequence|RSSI: valeurDB| tailleB] trameHEX"
    
    Notes
    -----
    Si un format non supporté est fourni, la méthode utilise 'nrf52' par défaut
    et enregistre un avertissement dans les logs.
    
    Exemple
    -------
    >>> sniffer = SniffeurZigbee()
    >>> sniffer.definir_format_entree('esp32h2')  # Configure le sniffeur pour les trames ESP32H2
    """
        if materiel.lower() not in ['nrf52', 'esp32h2']:
            logger.warning(f"Format d'entrée non pris en charge: {materiel}. Utilisation de 'nrf52'.")
            self.materiel = 'nrf52'
        else:
            self.materiel = materiel.lower()
            
        logger.info(f"Format d'entrée défini sur {self.materiel}")

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
        return '/dev/ttyUSB0'  # Ou peripheriques[0] pour utiliser le premier trouvé

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
            
            # Configurer le canal de capture
            self._configurer_canal()
            if self.materiel == 'esp32h2':
                #Envoie sur le port serie la commande pour activer le mode sniffer
                self.port_serie.write(bytes("#CMD#MODE_SNIFF",'utf-8'))
                print("Mode sniffer activé")
            
        except serial.SerialException as e:
            logger.error(f"Erreur de configuration du sniffer : {e}")
            self._fermer_port_serie()
            raise

    def _configurer_canal(self):
        """
        Configure le canal de capture ZigBee sur le périphérique.
        
        Cette méthode envoie une commande au périphérique pour définir
        le canal ZigBee à utiliser pour la capture.
        """
        try:
            # Vérifier que le canal est valide (11-26 pour ZigBee)
            if not (11 <= self.canal <= 26):
                logger.warning(f"Canal {self.canal} hors plage, utilisation du canal 13 par défaut")
                self.canal = 13
            
            # Envoyer la commande au périphérique pour configurer le canal
            # Format de commande dépend du firmware du périphérique
            commande = f"CHANNEL {self.canal}\r\n".encode('utf-8')
            self.port_serie.write(commande)
            time.sleep(0.5)  # Laisser le temps au périphérique de traiter la commande
            
            reponse = self.port_serie.readline().decode('utf-8').strip()
            logger.info(f"Configuration du canal {self.canal}: {reponse}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la configuration du canal: {e}")

    def definir_canal(self, nouveau_canal):
        """
        Définit un nouveau canal pour la capture.
        
        Si le sniffer est en cours d'exécution, il est arrêté puis redémarré
        avec le nouveau canal.
        
        Paramètres
        ----------
        nouveau_canal : int
            Le nouveau canal ZigBee à utiliser (11-26).
        """
        if not (11 <= nouveau_canal <= 26):
            logger.warning(f"Canal {nouveau_canal} invalide. Utilisation de la plage 11-26 uniquement.")
            return
            
        etait_en_cours = self.est_en_cours
        if etait_en_cours:
            self.arreter_sniffer()
            time.sleep(1)  # Attendre l'arrêt complet
            
        self.canal = nouveau_canal
        logger.info(f"Canal modifié: {self.canal}")
        
        if etait_en_cours:
            self.demarrer_sniffer()

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
    
    Cette méthode est conçue pour être exécutée dans un thread dédié. Elle lit en continu
    les données du port série configuré et les met dans une file d'attente pour traitement ultérieur.
    Le format des paquets dépend du format d'entrée configuré ('nrf52' ou 'esp32h2').
    
    La méthode s'exécute en boucle tant que l'attribut 'est_en_cours' est True.
    Pour chaque ligne lue depuis le port série, elle vérifie si le format correspond
    au format d'entrée configuré avant de l'ajouter à la file.
    
    Mécanismes de vérification appliqués:
    - Pour le format 'nrf52': vérifie que la chaîne contient "received:"
    - Pour le format 'esp32h2': vérifie que la chaîne contient "]" et a une longueur > 10
    
    Gestion d'erreurs:
    - Les erreurs de décodage Unicode sont traitées avec l'option 'errors=replace' et journalisées
    - Les exceptions de port série entraînent l'arrêt de la capture
    - Si la file de paquets est pleine, les paquets sont ignorés et un avertissement est journalisé
    
    Notes
    -----
    Cette méthode nettoie les buffers d'entrée/sortie au démarrage pour éviter de
    traiter des données partielles ou obsolètes.
    
    Le port série est toujours fermé proprement dans le bloc 'finally', quelle que soit
    la raison de l'arrêt de la méthode.
    """
        try:
            logger.info(f"Début de capture sur {self.interface}, canal {self.canal}, format d'entrée: {self.materiel}")
            # Vider les buffers avant de démarrer
            self.port_serie.reset_input_buffer()
            self.port_serie.reset_output_buffer()
            while self.est_en_cours:
                if self.port_serie.in_waiting:
                    try:
                        donnees_brutes = self.port_serie.readline().decode('utf-8', errors='replace').strip()
                        
                        # Vérifier si les données sont au format attendu avant de les mettre en file
                        if self.materiel == 'nrf52' and donnees_brutes and "received:" in donnees_brutes:
                            try:
                                self.file_paquets.put_nowait(donnees_brutes)
                            except queue.Full:
                                logger.warning("File de paquets pleine, paquet ignoré.")
                        elif self.materiel == 'esp32h2' and donnees_brutes and "]" in donnees_brutes and len(donnees_brutes) > 10:
                            try:
                                self.file_paquets.put_nowait(donnees_brutes)
                            except queue.Full:
                                logger.warning("File de paquets pleine, paquet ignoré.")
                    except UnicodeDecodeError as e:
                        logger.warning(f"Erreur de décodage des données série: {e}")
                        self.port_serie.reset_input_buffer()
        except serial.SerialException as e:
            logger.error(f"Erreur de port série : {e}")
        finally:
            self._fermer_port_serie()

    def _traiter_paquets(self, decoder=DecodeurTrameZigbee()):
        """
    Traite les paquets capturés en les décodant et en les stockant dans la liste des captures.
    
    Cette méthode est conçue pour être exécutée dans un thread dédié, parallèlement à celui
    qui capture les paquets. Elle récupère les paquets depuis la file d'attente, les décode
    en utilisant le décodeur fourni et stocke les résultats dans la liste des captures.
    
    Le traitement dépend du format d'entrée configuré ('nrf52' ou 'esp32h2') et utilise
    les méthodes spécifiques _traiter_paquet_nrf52 ou _traiter_paquet_esp32h2.
    
    Paramètres
    ----------
    decoder : DecodeurTrameZigbee, optionnel
        Instance de décodeur à utiliser pour interpréter les trames. Par défaut,
        une nouvelle instance de DecodeurTrameZigbee est créée.
    
    Notes
    -----
    - La méthode s'exécute en boucle tant que l'attribut 'est_en_cours' est True
    - Un timeout est utilisé lors de la récupération des paquets pour permettre une
      vérification régulière de la condition d'arrêt (est_en_cours)
    - Les erreurs de traitement d'un paquet spécifique sont attrapées et journalisées,
      sans interrompre le traitement des autres paquets
    - Les exceptions de type queue.Empty sont ignorées (timeout de récupération de paquet)
    """
        while self.est_en_cours:
            try:
                paquet = self.file_paquets.get(timeout=1)
                try:
                    # Traitement selon le format d'entrée
                    if self.materiel == 'nrf52':
                        self._traiter_paquet_nrf52(paquet, decoder)
                    elif self.materiel == 'esp32h2':
                        self._traiter_paquet_esp32h2(paquet, decoder)
                    else:
                        logger.warning(f"materiel non reconnu: {self.materiel}")
                except Exception as e:
                    logger.error(f"Erreur lors du traitement du paquet : {e}", exc_info=True)
            except queue.Empty:
                pass
    def _traiter_paquet_nrf(self, paquet, decoder):
        """
    Traite un paquet au format nRF52840.
    
    Cette méthode analyse les paquets capturés depuis un adaptateur basé sur le nRF52840.
    Le format attendu est: "received: [trame_hex] power: [rssi] lqi: [lqi] time: [timestamp]".
    La méthode extrait les données et métadonnées, puis utilise le décodeur pour interpréter
    la trame ZigBee.
    
    Paramètres
    ----------
    paquet : str
        Chaîne de caractères représentant le paquet à traiter au format nRF52840.
    decoder : DecodeurTrameZigbee
        Instance de décodeur à utiliser pour interpréter la trame.
    
    Notes
    -----
    Les métadonnées extraites incluent:
    - power (RSSI): puissance du signal reçu en dBm
    - lqi: indicateur de qualité de la liaison
    - timestamp: horodatage de la capture
    - trame_brute: données brutes de la trame en hexadécimal
    - canal: canal ZigBee utilisé
    
    Si le format de sortie est 'pcap', la trame est également ajoutée au fichier PCAP.
    
    La méthode journalise un avertissement si la trame ne peut pas être décodée ou
    si le format du paquet ne correspond pas au format attendu.
    """
        import re
        pattern = r"received: ([0-9a-fA-F]+) power: ([-\d]+) lqi: (\d+) time: (\d+)"
        match = re.search(pattern, paquet)
        
        if match:
            paquet_received = match.group(1)
            power = match.group(2)
            lqi = match.group(3)
            timestamp = match.group(4)
            
            paquet_bytes = bytes.fromhex(paquet_received)
            
            metadonnees = {
                'power': power,
                'lqi': lqi,
                'timestamp': timestamp,
                'trame_brute': paquet_received,
                'canal': self.canal
            }
            
            # Si PCAP est activé, ajouter la trame au fichier PCAP
            if self.format_sortie == 'pcap' and self.pcap_writer:
                self._ajouter_trame_pcap(paquet_bytes, metadonnees)
            
            decoded_frame = decoder.decoder_trame_zigbee(paquet_bytes)
            if decoded_frame:
                decoded_frame['metadonnees'] = metadonnees
                self.captures.append(decoded_frame)
            else:
                logger.warning(f"Impossible de décoder la trame : {paquet_received}")
        else:
            logger.warning(f"Format de paquet KillerBee non reconnu: {paquet}")

    def _traiter_paquet_esp32h2(self, paquet, decoder):
        """
    Traite un paquet au format ESP32H2.
    
    Cette méthode analyse les paquets capturés depuis un adaptateur basé sur l'ESP32H2.
    Le format attendu est: "[ sequence|RSSI: valeurDB| tailleB] trameHEX".
    Exemple: "[ 22959|RSSI: -54dB| 10B] 0308A1FFFFFFFF07C009"
    
    La méthode extrait les données et métadonnées, puis utilise le décodeur pour interpréter
    la trame ZigBee.
    
    Paramètres
    ----------
    paquet : str
        Chaîne de caractères représentant le paquet à traiter au format ESP32H2.
    decoder : DecodeurTrameZigbee
        Instance de décodeur à utiliser pour interpréter la trame.
    
    Notes
    -----
    Les métadonnées extraites incluent:
    - power (RSSI): puissance du signal reçu en dBm
    - lqi: toujours défini à '0' car non fourni par l'ESP32H2
    - timestamp: horodatage de la capture (généré par l'heure système actuelle)
    - trame_brute: données brutes de la trame en hexadécimal
    - canal: canal ZigBee utilisé
    - sequence: numéro de séquence fourni par l'ESP32H2
    - taille: taille de la trame en octets
    
    Si le format de sortie est 'pcap', la trame est également ajoutée au fichier PCAP.
    
    La méthode journalise un avertissement si la trame ne peut pas être décodée ou
    si le format du paquet ne correspond pas au format attendu.
    """
        import re
        # Pattern pour extraire les informations du format ESP32H2
        pattern = r"\[\s*(\d+)\|RSSI:\s*([-\d]+)dB\|\s*(\d+)B\]\s*([0-9a-fA-F]+)"
        match = re.search(pattern, paquet)
        
        if match:
            sequence = match.group(1)
            rssi = match.group(2)
            taille = match.group(3)
            trame_hex = match.group(4)
            
            paquet_bytes = bytes.fromhex(trame_hex)
            
            # Utiliser le temps actuel comme timestamp si non disponible
            timestamp = int(time.time() * 1000)
            
            metadonnees = {
                'power': rssi,  # Utiliser RSSI comme power
                'lqi': '0',     # LQI non disponible, utiliser 0 comme valeur par défaut
                'timestamp': str(timestamp),
                'trame_brute': trame_hex,
                'canal': self.canal,
                'sequence': sequence,
                'taille': taille
            }
            
            # Si PCAP est activé, ajouter la trame au fichier PCAP
            if self.format_sortie == 'pcap' and self.pcap_writer:
                self._ajouter_trame_pcap(paquet_bytes, metadonnees)
                
            decoded_frame = decoder.decoder_trame_zigbee(paquet_bytes)
            if decoded_frame:
                decoded_frame['metadonnees'] = metadonnees
                self.captures.append(decoded_frame)
            else:
                logger.warning(f"Impossible de décoder la trame ESP32H2 : {trame_hex}")
        else:
            logger.warning(f"Format de paquet ESP32H2 non reconnu: {paquet}")

    def _initialiser_pcap(self):
        """
    Initialise le fichier PCAP pour sauvegarder les trames.
    
    Cette méthode crée un fichier PCAP pour stocker les trames capturées lorsque
    le format de sortie est configuré sur 'pcap'. Elle s'assure que le fichier
    a l'extension .pcap et configure le PcapWriter de Scapy avec les paramètres
    appropriés pour les trames IEEE 802.15.4 (ZigBee).
    
    Effets de bord:
    - Modifie l'extension du fichier de sortie si nécessaire
    - Initialise l'attribut self.pcap_writer
    
    Notes
    -----
    - Utilise le linktype 195 qui correspond au format IEEE 802.15.4
    - En cas d'erreur lors de l'initialisation du fichier PCAP,
      le format de sortie est automatiquement basculé vers 'json'
    - La synchronisation forcée (sync=True) garantit que les données sont écrites
      immédiatement sur le disque, ce qui est utile en cas d'arrêt inattendu
    """
        if self.format_sortie == 'pcap':
            try:
                # S'assurer que l'extension est .pcap
                if not self.fichier_sortie.endswith('.pcap'):
                    self.fichier_sortie = os.path.splitext(self.fichier_sortie)[0] + '.pcap'
                
                # Créer le PcapWriter avec les bons paramètres
                # linktype=195 pour IEEE 802.15.4 (Zigbee utilise cette couche physique)
                self.pcap_writer = scapy.PcapWriter(self.fichier_sortie, linktype=195, append=False, sync=True)
                logger.info(f"Fichier PCAP initialisé: {self.fichier_sortie}")
            except Exception as e:
                logger.error(f"Erreur lors de l'initialisation du fichier PCAP: {e}")
                self.format_sortie = 'json'
                logger.info(f"Format de sortie basculé sur JSON en raison de l'erreur")

    def _ajouter_trame_pcap(self, trame_bytes, metadonnees):
        """
    Ajoute une trame au fichier PCAP.
    
    Cette méthode convertit les données brutes d'une trame en un paquet Scapy
    Dot15d4FCS, y associe les métadonnées pertinentes (LQI, RSSI, timestamp),
    puis l'écrit dans le fichier PCAP.
    
    Paramètres
    ----------
    trame_bytes : bytes
        Les données brutes de la trame en format binaire.
    metadonnees : dict
        Dictionnaire contenant les métadonnées associées à la trame.
        Doit contenir au minimum les clés 'lqi', 'power' et 'timestamp'.
    
    Notes
    -----
    - La méthode initialise un objet Dot15d4FCS de Scapy avec les données brutes
    - Le FCS (Frame Check Sequence) est effacé pour que Scapy le recalcule automatiquement
    - Les valeurs LQI, RSSI et timestamp sont extraites des métadonnées et
      associées au paquet Scapy
    - Le timestamp est converti de millisecondes à secondes (format PCAP)
    - Les erreurs lors de l'ajout sont capturées et journalisées sans interrompre
      le processus de capture
    """
        try:
            # Créer un paquet Scapy à partir des données
            dot15d4_pkt = Dot15d4FCS(trame_bytes) 
            dot15d4_pkt.fcs = None  # Forcer Scapy à recalculer le FCS
            
            
            dot15d4_pkt.lqi = int(metadonnees['lqi'])
            dot15d4_pkt.rssi = int(metadonnees['power'])
            
            
            timestamp = float(metadonnees['timestamp']) / 1000.0
            dot15d4_pkt.time = timestamp

            self.pcap_writer.write(dot15d4_pkt)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de la trame au fichier PCAP: {e}")

    def demarrer_sniffer(self):
        """
        Démarre le sniffer pour capturer les trames ZigBee.

        Cette méthode configure le port série puis lance deux threads en mode daemon :
            - Un thread pour la capture des paquets (_capturer_paquets).
            - Un thread pour le traitement et le décodage des paquets (_traiter_paquets).

        Si le format de sortie est PCAP, initialise également le fichier PCAP.

        En cas d'erreur lors du démarrage, un message d'erreur est logué.
        """
        try:
            self.est_en_cours = True
            self._configurer_sniffer()
            
            # Initialiser le fichier PCAP si nécessaire
            if self.format_sortie == 'pcap':
                self._initialiser_pcap()
            
                
            threading.Thread(target=self._capturer_paquets, daemon=True).start()
            threading.Thread(target=self._traiter_paquets, daemon=True).start()
            
            logger.info(f"Sniffer démarré sur le canal {self.canal} (format de sortie: {self.format_sortie})")
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du sniffer : {e}")
            self.est_en_cours = False

    def arreter_sniffer(self):
        """
        Arrête le sniffer.

        Cette méthode modifie le drapeau d'exécution afin d'arrêter les threads de capture 
        et de traitement. Un message d'information est logué pour indiquer l'arrêt.
        
        Si le format de sortie est PCAP, ferme également le fichier PCAP.
        """
        self.est_en_cours = False
        
        # Fermer le fichier PCAP si nécessaire
        if self.format_sortie == 'pcap' and self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
            
        logger.info("Arrêt du sniffer")

    def sauvegarder_captures(self):
        """
        Sauvegarde les trames capturées dans un fichier JSON ou PCAP.

        Selon le format de sortie sélectionné, cette méthode sauvegarde les captures
        soit au format JSON soit au format PCAP.

        Lève
        ----
        Exception
            Si une erreur survient lors de l'écriture dans le fichier.
        """
        try:
            if self.format_sortie == 'json':
                # S'assurer que l'extension est .json
                if not self.fichier_sortie.endswith('.json'):
                    self.fichier_sortie = os.path.splitext(self.fichier_sortie)[0] + '.json'
                
                with open(self.fichier_sortie, 'w', encoding='utf-8') as f:
                    json.dump(self.captures, f, indent=2, ensure_ascii=False)
                logger.info(f"Captures sauvegardées au format JSON dans {self.fichier_sortie}")
            
            elif self.format_sortie == 'pcap':
                # Le fichier PCAP est écrit en continu pendant la capture
                # On s'assure simplement qu'il est bien fermé
                if self.pcap_writer:
                    self.pcap_writer.close()
                    self.pcap_writer = None
                logger.info(f"Captures sauvegardées au format PCAP dans {self.fichier_sortie}")
            
            else:
                logger.warning(f"Format de sortie non reconnu: {self.format_sortie}")
        
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des captures : {e}")

    def definir_format_sortie(self, format_sortie):
        """
    Définit le format de sortie pour les captures.
    
    Cette méthode configure le format dans lequel les trames capturées seront
    sauvegardées. Deux formats sont supportés : JSON et PCAP. La méthode
    ajuste également l'extension du fichier de sortie pour correspondre au format choisi.
    
    Paramètres
    ----------
    format_sortie : str
        Format de sortie à utiliser. Valeurs acceptées:
        - 'json': sauvegarde les données sous forme de structure JSON
        - 'pcap': sauvegarde les trames dans un fichier PCAP lisible par Wireshark
    
    Effets de bord:
    - Modifie l'attribut self.format_sortie
    - Ajuste l'extension du fichier de sortie (self.fichier_sortie)
    
    Notes
    -----
    - Si un format non supporté est fourni, la méthode utilise 'json' par défaut
      et enregistre un avertissement dans les logs
    - L'extension du fichier de sortie est automatiquement mise à jour pour
      refléter le format choisi (.json ou .pcap)
    - Un message d'information est journalisé pour confirmer la configuration
    
    Exemple
    -------
    >>> sniffer = SniffeurZigbee(fichier_sortie='captures')
    >>> sniffer.definir_format_sortie('pcap')  # Fichier de sortie devient 'captures.pcap'
    """
        if format_sortie.lower() not in ['json', 'pcap']:
            logger.warning(f"Format de sortie non pris en charge: {format_sortie}. Utilisation de 'json'.")
            self.format_sortie = 'json'
        else:
            self.format_sortie = format_sortie.lower()
            
        # Adapter l'extension du fichier de sortie
        nom_base, _ = os.path.splitext(self.fichier_sortie)
        self.fichier_sortie = nom_base + ('.' + self.format_sortie)
        
        logger.info(f"Format de sortie défini sur {self.format_sortie}, fichier de sortie: {self.fichier_sortie}")

