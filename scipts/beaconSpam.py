import threading
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

# Fonction pour envoyer une Beacon Request
def send_beacon_request():
    # Créer le paquet Beacon Request (Propriétaire de la carte Wi-Fi dans l'adresse source)
    beacon_req = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2='00:11:22:33:44:55', addr3='ff:ff:ff:ff:ff:ff') / Dot11Beacon(cap='ESS') / Dot11Elt(ID='SSID', info='TestSSID', len=len('TestSSID'))
    
    # Envoyer le paquet sur le réseau
    sendp(beacon_req, iface="wlp1s0", verbose=False)  # Assurez-vous que l'interface est en mode moniteur (ex: wlan0mon)

# Fonction pour démarrer plusieurs threads
def start_beacon_requests(num_threads):
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_beacon_request)
        thread.start()
        threads.append(thread)

    # Attendre que tous les threads se terminent
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    # Nombre de threads à lancer (par exemple, 500 threads pour envoyer 500 Beacon Requests simultanément)
    num_threads = 500
    
    # Démarrer l'envoi des Beacon Requests en boucle multi-threadée
    while True:
        start_beacon_requests(num_threads)
        print(f"{num_threads} Beacon Requests envoyées")
