"""
Ce module implémente un spammer de paquets Beacon WiFi. Il permet de configurer une interface réseau pour envoyer des paquets Beacon sur un canal spécifique, surveiller le nombre de paquets envoyés, et gérer l'envoi en utilisant des threads.

Classes
-------
WifiSpammer : Classe pour gérer l'envoi de paquets Beacon WiFi.
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
    Classe pour spammer le réseau WiFi avec des paquets Beacon.

    Attributes
    ----------
    interface : str
        Interface réseau à utiliser pour l'envoi des paquets.
    channel : int
        Canal WiFi sur lequel envoyer les paquets Beacon.
    ssid : str
        SSID à diffuser dans les paquets Beacon.
    packet_queue : queue.Queue
        File d'attente des paquets à envoyer.
    running : bool
        Indicateur d'état de fonctionnement de l'envoi des paquets.
    sent_count : int
        Nombre de paquets envoyés.
    start_time : float
        Heure de début de l'envoi des paquets, utilisée pour calculer le taux d'envoi.
    """

    def __init__(self, interface: str, channel: int = 1, ssid: str = "JamESP", max_queue_size: int = 1000):
        """
        Initialise un spammer WiFi.

        Parameters
        ----------
        interface : str
            Interface réseau à utiliser pour l'envoi des paquets.
        channel : int, optional
            Canal WiFi sur lequel les paquets Beacon seront envoyés (par défaut : 1).
        ssid : str, optional
            SSID à diffuser dans les paquets Beacon (par défaut : "JamESP").
        max_queue_size : int, optional
            Taille maximale de la file d'attente pour les paquets (par défaut : 1000).
        """
        self.interface = interface
        self.channel = 1
        self.ssid = ssid
        self.packet_queue = Queue(maxsize=max_queue_size)
        self.running = False
        self.sent_count = 0
        self.start_time = 0
        

    def set_channel(self):
        """
        Configure l'interface WiFi sur le canal spécifié.

        Raises
        ------
        Exception
            Si une erreur survient lors de la configuration du canal.
        """
        try:
            os.system(f"ifconfig {self.interface} down")
            os.system(f"iwconfig {self.interface} mode monitor")
            os.system(f"iwconfig {self.interface} channel {self.channel}")
            os.system(f"ifconfig {self.interface} up")
            print(f"Canal configuré sur {self.channel}")
        except Exception as e:
            print(f"Erreur lors de la configuration du canal : {e}")

    def create_beacon_packet(self) -> RadioTap:
        """
        Crée un paquet Beacon WiFi.

        Returns
        -------
        scapy.layers.dot11.RadioTap
            Un paquet RadioTap contenant un Beacon WiFi configuré avec le SSID et le canal.
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
        Gère l'envoi des paquets Beacon en continu.

        Notes
        -----
        Cette méthode est exécutée dans un thread pour envoyer les paquets Beacon par lots de 10.
        """
        beacon_packet = self.create_beacon_packet()

        while self.running:
            try:
                sendp(beacon_packet, iface=self.interface, verbose=False, count=10)
                with threading.Lock():
                    self.sent_count += 10
            except Exception as e:
                print(f"Erreur lors de l'envoi du paquet : {e}")
                time.sleep(0.1)  # Temporisation en cas d'erreur

    def monitor_progress(self):
        """
        Surveille la progression de l'envoi des paquets Beacon.

        Affiche en temps réel le nombre de paquets envoyés et le taux d'envoi en paquets par seconde.
        """
        while self.running:
            elapsed_time = time.time() - self.start_time
            rate = self.sent_count / elapsed_time if elapsed_time > 0 else 0
            print(f"Envoyé {self.sent_count} paquets sur le canal {self.channel} | Taux : {rate:.2f} paquets/sec")
            time.sleep(1)

    def start_scan(self, num_sender_threads: int = 4):
        """
        Démarre le processus d'envoi des paquets Beacon.

        Parameters
        ----------
        num_sender_threads : int, optional
            Nombre de threads utilisés pour envoyer les paquets (par défaut : 4).

        Notes
        -----
        Configure le canal WiFi, lance plusieurs threads pour envoyer les paquets et démarre un thread pour surveiller
        le progrès de l'envoi.
        """
        self.set_channel()

        self.running = True
        self.start_time = time.time()

        sender_threads = []
        for _ in range(num_sender_threads):
            thread = threading.Thread(target=self.packet_sender)
            thread.daemon = True
            thread.start()
            sender_threads.append(thread)

        monitor_thread = threading.Thread(target=self.monitor_progress)
        monitor_thread.daemon = True
        monitor_thread.start()

        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nArrêt du scan...")
            
            self.running = False

            for thread in sender_threads:
                thread.join()
            monitor_thread.join()
            os.system(f"ifconfig {self.interface} down")
            os.system(f"iwconfig {self.interface} mode managed")
            os.system(f"ifconfig {self.interface} up")

