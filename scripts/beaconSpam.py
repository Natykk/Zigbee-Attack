"""
Ce module implémente un spammer de beacons WiFi avec des informations sur la vitesse d'envoi des paquets. 
"""

import threading
from queue import Queue
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
import time
import os
from typing import Optional

class WifiSpammer:
    """
    @class WifiSpammer
    @brief Classe pour spammer le réseau WiFi avec des paquets Beacon.
    @details Cette classe gère l'envoi de paquets Beacon WiFi de manière multithreadée. Elle permet de configurer
             le canal, de créer les paquets Beacon, de les envoyer et de surveiller le progrès de l'envoi.
    """

    def __init__(self, interface: str, channel: int = 1, ssid: str = "TestSSID", max_queue_size: int = 1000):
        """
        @brief Constructeur de la classe WifiSpammer.
        
        @param interface: Interface réseau à utiliser pour l'envoi des paquets.
        @param channel: Canal WiFi sur lequel les paquets Beacon seront envoyés (par défaut : 1).
        @param ssid: SSID à diffuser dans les paquets Beacon (par défaut : "TestSSID").
        @param max_queue_size: Taille maximale de la file d'attente pour les paquets (par défaut : 1000).
        """
        self.interface = interface
        self.channel = channel
        self.ssid = ssid
        self.packet_queue = Queue(maxsize=max_queue_size)
        self.running = False
        self.sent_count = 0
        self.start_time = 0

    def set_channel(self):
        """
        @brief Configure l'interface WiFi sur le canal spécifié.
        
        @exception Exception: Si une erreur survient lors de la configuration du canal.
        """
        try:
            # os.system(f"iwconfig {self.interface} channel {self.channel}")
            print(f"Canal configuré sur {self.channel}")
        except Exception as e:
            print(f"Erreur lors de la configuration du canal : {e}")

    def create_beacon_packet(self) -> RadioTap:
        """
        @brief Crée un paquet Beacon WiFi.
        
        @return: Un paquet de type RadioTap, contenant un paquet Beacon WiFi configuré avec le SSID et le canal.
        """
        return (RadioTap()
                / Dot11(type=0, subtype=8,
                        addr1='ff:ff:ff:ff:ff:ff',
                        addr2='00:11:22:33:44:55',
                        addr3='ff:ff:ff:ff:ff:ff')
                / Dot11Beacon(cap='ESS')
                / Dot11Elt(ID='SSID', info=self.ssid)
                / Dot11Elt(ID='DSset', info=chr(self.channel)))

    def packet_sender(self):
        """
        @brief Fonction dédiée à la gestion de l'envoi des paquets Beacon.
        
        @details Cette fonction est exécutée dans un thread pour envoyer en continu les paquets Beacon. Les paquets
                 sont envoyés par lots de 10 pour optimiser les performances.
        """
        beacon_packet = self.create_beacon_packet()

        while self.running:
            try:
                # Envoi par lots de paquets
                sendp(beacon_packet, iface=self.interface, verbose=False, count=10)
                with threading.Lock():
                    self.sent_count += 10
            except Exception as e:
                print(f"Erreur lors de l'envoi du paquet : {e}")
                time.sleep(0.1)  # Temporisation en cas d'erreur

    def monitor_progress(self):
        """
        @brief Surveille et rapporte la progression de l'envoi des paquets.
        
        @details Cette fonction est exécutée dans un thread pour afficher en temps réel le nombre de paquets envoyés
                 ainsi que le taux d'envoi en paquets par seconde.
        """
        while self.running:
            elapsed_time = time.time() - self.start_time
            rate = self.sent_count / elapsed_time if elapsed_time > 0 else 0
            print(f"Envoyé {self.sent_count} paquets sur le canal {self.channel} | Taux : {rate:.2f} paquets/sec")
            time.sleep(1)

    def start_scan(self, num_sender_threads: int = 4):
        """
        @brief Démarre le processus d'envoi des paquets Beacon avec plusieurs threads.
        
        @param num_sender_threads: Nombre de threads d'envoi (par défaut : 4). Chaque thread envoie des paquets Beacon.
        
        @details Cette méthode configure d'abord le canal WiFi, puis lance plusieurs threads pour envoyer les paquets
                 Beacon. Un thread séparé est utilisé pour surveiller le progrès de l'envoi.
        """
        self.set_channel()

        self.running = True
        self.start_time = time.time()

        # Lancement des threads d'envoi
        sender_threads = []
        for _ in range(num_sender_threads):
            thread = threading.Thread(target=self.packet_sender)
            thread.daemon = True
            thread.start()
            sender_threads.append(thread)

        # Démarrage du thread de surveillance
        monitor_thread = threading.Thread(target=self.monitor_progress)
        monitor_thread.daemon = True
        monitor_thread.start()

        try:
            # Maintient le thread principal actif
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nArrêt du scan...")
            self.running = False

            # Attend que tous les threads se terminent
            for thread in sender_threads:
                thread.join()
            monitor_thread.join()

if __name__ == "__main__":
    """
    Exemple d'utilisation pour démarrer l'envoi de paquets Beacon sur le canal 1 avec 30 threads d'envoi.
    """
    scanner = WifiSpammer(interface="wlp1s0", channel=1)
    # scanner.start_scan(num_sender_threads=30)
