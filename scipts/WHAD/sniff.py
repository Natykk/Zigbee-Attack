import pyshark
import logging
import threading
import queue
import time
import json
import glob
from datetime import datetime

# Configurer la journalisation
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def trouver_peripheriques_serie_usb():
    """
    Trouver les périphériques série USB disponibles
    
    :return: Liste des chemins de périphériques série USB
    """
    return glob.glob('/dev/ttyACM*')

class SniffeurZigbee:
    def __init__(self, canal=13, fichier_sortie='captures_zigbee.json'):
        """
        Initialiser le Sniffeur Zigbee avec sélection dynamique de périphérique
        
        :param canal: Canal Zigbee à sniffer
        :param fichier_sortie: Fichier pour sauvegarder les captures de paquets
        """
        self.canal = canal
        self.fichier_sortie = fichier_sortie
        self.file_paquets = queue.Queue()
        self.en_cours = False
        self.capture = None
        self.interface = self.selectionner_interface()
    
    def selectionner_interface(self):
        """
        Sélectionner le premier périphérique série USB disponible
        
        :return: Chemin de l'interface sélectionnée
        """
        peripheriques = trouver_peripheriques_serie_usb()
        if not peripheriques:
            raise RuntimeError("Aucun périphérique série USB trouvé")
        
        logger.info(f"Périphériques disponibles : {peripheriques}")
        peripherique_selectionne = peripheriques[0]
        logger.info(f"Périphérique sélectionné : {peripherique_selectionne}")
        return peripherique_selectionne
    
    def capturer_paquets(self):
        """
        Capturer les paquets et les placer dans la file d'attente
        """
        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interface, 
                display_filter=f"wpan and chan == {self.canal}",
                debug=True  # Activer le mode débogage
            )
            
            logger.info(f"Démarrage de la capture sur {self.interface}, canal {self.canal}")
            
            for paquet in self.capture.sniff_continuously():
                if not self.en_cours:
                    break
                self.file_paquets.put(paquet)
        
        except Exception as e:
            logger.error(f"Erreur de capture : {e}")
        finally:
            if self.capture:
                self.capture.close()
    
    def traiter_paquets(self):
        """
        Traiter les paquets de la file d'attente et les sauvegarder dans un fichier
        """
        captures = []
        try:
            while self.en_cours:
                try:
                    paquet = self.file_paquets.get(timeout=1)
                    metadata = self.extraire_metadata_paquet(paquet)
                    captures.append(metadata)
                
                except queue.Empty:
                    continue
        
        except Exception as e:
            logger.error(f"Erreur de traitement : {e}")
        
        finally:
            # Sauvegarder les paquets capturés en JSON
            with open(self.fichier_sortie, 'w') as f:
                json.dump(captures, f, indent=2)
            logger.info(f"Captures sauvegardées dans {self.fichier_sortie}")
    
    def extraire_metadata_paquet(self, paquet):
        """
        Extraire les métadonnées détaillées du paquet capturé
        
        :param paquet: Paquet Pyshark
        :return: Dictionnaire avec les métadonnées du paquet
        """
        metadata = {
            'horodatage': datetime.now().isoformat(),
            'paquet_brut': str(paquet)
        }
        
        # Extraire dynamiquement les informations de couche
        couches = ['wpan', 'zbee_nwk', 'zbee_aps', 'zbee_zcl']
        for couche in couches:
            if hasattr(paquet, couche):
                donnees_couche = {}
                objet_couche = getattr(paquet, couche)
                
                # Extraire dynamiquement tous les attributs
                for attr in dir(objet_couche):
                    if not attr.startswith('_'):
                        try:
                            valeur = getattr(objet_couche, attr)
                            donnees_couche[attr] = str(valeur)
                        except Exception:
                            pass
                
                metadata[couche] = donnees_couche
        
        return metadata
    
    def commencer_sniffing(self, duree=60):
        """
        Commencer le sniffing avec des threads séparés
        
        :param duree: Durée de capture en secondes
        """
        self.en_cours = True
        
        # Créer les threads
        thread_capture = threading.Thread(target=self.capturer_paquets)
        thread_traitement = threading.Thread(target=self.traiter_paquets)
        
        # Démarrer les threads
        thread_capture.start()
        thread_traitement.start()
        
        # Attendre la durée spécifiée
        time.sleep(duree)
        
        # Arrêter les threads
        self.en_cours = False
        thread_capture.join()
        thread_traitement.join()

def main():
    sniffeur = SniffeurZigbee(canal=13)
    sniffeur.commencer_sniffing()

if __name__ == "__main__":
    main()