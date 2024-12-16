import serial
import logging
import threading
import queue
import time
import json
import glob
from datetime import datetime
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
import binascii
import math

# Configuration de la journalisation
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s : %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sniffeur_zigbee.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

def trouver_peripheriques_serie():
    """
    Trouve les périphériques série USB disponibles

    :return: Liste des chemins des périphériques série
    """
    return glob.glob('/dev/ttyACM*')

def analyser_paquet_zigbee(donnees_brutes):
    """
    Analyse un paquet Zigbee brut reçu par nRF52840.

    Args:
        donnees_brutes (str): Chaîne de données de paquet brut

    Returns:
        dict: Informations du paquet analysé
    """
    try:
        composants = donnees_brutes.split()
        donnees_analysees = {
            'adresse': None,
            'puissance': None,
            'lqi': None,
            'horodatage': None
        }

        if len(composants) > 1 and composants[0] == 'received:':
            donnees_analysees['adresse'] = composants[1]

        try:
            index_puissance = composants.index('power:') + 1
            donnees_analysees['puissance'] = float(composants[index_puissance])
        except (ValueError, IndexError):
            logger.warning("Impossible d'analyser la valeur de puissance")

        try:
            index_lqi = composants.index('lqi:') + 1
            donnees_analysees['lqi'] = int(composants[index_lqi])
        except (ValueError, IndexError):
            logger.warning("Impossible d'analyser la valeur du LQI")

        try:
            index_temps = composants.index('time:') + 1
            donnees_analysees['horodatage'] = int(composants[index_temps])
        except (ValueError, IndexError):
            logger.warning("Impossible d'analyser l'horodatage")

        return donnees_analysees

    except Exception as e:
        logger.error(f"Erreur d'analyse du paquet Zigbee : {e}")
        return {
            'adresse': None,
            'puissance': None,
            'lqi': None,
            'horodatage': None
        }

def est_hexadecimal(chaine):
    """
    Vérifie si une chaîne est valide en hexadécimal.

    Args:
        chaine (str): La chaîne à vérifier

    Returns:
        bool: True si la chaîne est hexadécimale, False sinon
    """
    try:
        int(chaine, 16)
        return True
    except ValueError:
        return False

def decoder_trame_zigbee_complet(trame_hex):
    try:
        # Vérification du format de la trame
        print(trame_hex)
        if "received:" not in trame_hex:
            logger.error("Trame invalide, 'received:' introuvable")
            return None

        # Extraction de la trame hexadécimale
        trame_hex = trame_hex.split("received: ")[1].split(" ")[0]

        if not est_hexadecimal(trame_hex):
            logger.error(f"Trame non valide : {trame_hex}")
            return None

        trame_bytes = bytes.fromhex(trame_hex)

        

        resultat = {
            'metadata': {
                'longueur_totale': len(trame_bytes),
                'representation_hex': trame_hex
            },
            'entete_protocole': {},
            'adressage': {},
            'payload': {}
        }

        resultat['entete_protocole'] = {
            'premier_octet': {
                'hex': trame_bytes[0:1].hex(),
                'decimal': trame_bytes[0],
                'binaire': bin(trame_bytes[0]),
                'interpretations': {
                    'type_trame': 'Trame de données Zigbee' 
                    if trame_bytes[0] == 0x61 else 'Type de trame inconnu'
                }
            }
        }

        def decoder_adresse(adresse_bytes):
            return {
                'hex': adresse_bytes.hex(),
                'decimal_little_endian': int.from_bytes(adresse_bytes, 'little'),
                'decimal_big_endian': int.from_bytes(adresse_bytes, 'big'),
                'interpretations': {
                    'est_adresse_reseau': True,
                    'protocole': 'IEEE 802.15.4 / Zigbee'
                }
            }

        # si la liste des adresses est vide, on ne peut pas accéder à l'index 0
        if len(trame_bytes) < 20:
            return None
        
       
        
        resultat['adressage']['adresse_source'] = decoder_adresse(trame_bytes[4:12])
        resultat['adressage']['adresse_destination'] = decoder_adresse(trame_bytes[12:20])

        payload = trame_bytes[20:]
        resultat['payload'] = {
            'longueur': len(payload),
            'hex': payload.hex(),
            'analyse_sections': []
        }

       
        

        taille_segment = 8
        for i in range(0, len(payload), taille_segment):
            segment = payload[i:i+taille_segment]
            resultat['payload']['analyse_sections'].append({
            'hex': segment.hex(),
            'ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in segment)
        })

        resultat['analyse_cryptographique'] = {
            'entropie': calculer_entropie(payload),
            'distribution_bits': analyser_distribution_bits(payload)
        }

        

        return resultat

    except Exception as e:
        logger.error(f"Erreur de décodage complet de la trame : {e}")
        return None

def calculer_entropie(donnees):
    if not donnees:
        return 0.0

    comptage = {}
    for octet in donnees:
        comptage[octet] = comptage.get(octet, 0) + 1

    total = len(donnees)
    return -sum((c / total) * math.log2(c / total) for c in comptage.values())

def analyser_distribution_bits(donnees):
    bits_1 = sum(bin(b).count('1') for b in donnees)
    total_bits = len(donnees) * 8
    if total_bits == 0:
        logger.warning("Les données sont vides, distribution des bits définie à 0.")
        return {
            'bits_1': 0,
            'bits_0': 0,
            'pourcentage_1': 0.0,
            'pourcentage_0': 0.0
        }
    return {
        'bits_1': bits_1,
        'bits_0': total_bits - bits_1,
        'pourcentage_1': (bits_1 / total_bits) * 100,
        'pourcentage_0': ((total_bits - bits_1) / total_bits) * 100
    }



def decrypt_zigbee_payload(payload_hex, cle_hex):
    try:
        payload = bytes.fromhex(payload_hex)
        cle = bytes.fromhex(cle_hex)

        
        nonce = payload[:13]  # Premier 13 octets pour le nonce
        tag = payload[-16:]   # Derniers 16 octets pour le tag
        donnees_chiffrees = payload[13:-16]  # Données chiffrées

        cipher = AES.new(cle, AES.MODE_CCM, nonce=nonce, mac_len=16)
        
        # Déchiffrement avec vérification du MAC
        try:
            payload_dechiffre = cipher.decrypt_and_verify(donnees_chiffrees, tag)
            return {
                'succes': True,
                'nonce': nonce.hex(),
                'tag': tag.hex(),
                'payload_dechiffre': payload_dechiffre.decode('utf-8', errors='ignore')
            }
        except ValueError as e:
            return {'succes': False, 'erreur': f"Erreur de vérification du MAC : {str(e)}"}
    except Exception as e:
        return {'succes': False, 'erreur': f"Erreur de déchiffrement : {str(e)}"}

    
class SniffeurZigbee:
    def __init__(self, canal=13, fichier_sortie='captures_zigbee.json', vitesse_bauds=115200):
        self.canal = canal
        self.fichier_sortie = fichier_sortie
        self.vitesse_bauds = vitesse_bauds
        self.file_paquets = queue.Queue(maxsize=1000)
        self.est_en_cours = False
        self.port_serie = None
        self.interface = self._selectionner_interface()
        self.captures = []
        self.cle_dechiffrement = "9b9494920170aeed67e90ce7d672face"

    def _selectionner_interface(self):
        peripheriques = trouver_peripheriques_serie()
        if not peripheriques:
            raise RuntimeError("Aucun périphérique série USB trouvé")

        logger.info(f"Périphériques disponibles : {peripheriques}")
        return peripheriques[0]

    def _configurer_sniffer(self):
        try:
            self.port_serie = serial.Serial(
                self.interface,
                baudrate=self.vitesse_bauds,
                timeout=1
            )
            logger.info(f"Configuration du sniffer sur {self.interface}")
        except serial.SerialException as e:
            logger.error(f"Erreur de configuration du sniffer : {e}")
            self._fermer_port_serie()
            raise

    def _fermer_port_serie(self):
        if self.port_serie and self.port_serie.is_open:
            self.port_serie.close()

    def _capturer_paquets(self):
        try:
            logger.info(f"Début de capture sur {self.interface}, canal {self.canal}")
            while self.est_en_cours:
                if self.port_serie.in_waiting:
                    donnees_brutes = self.port_serie.readline().decode('utf-8').strip()
                    if donnees_brutes:
                        try:
                            self.file_paquets.get_nowait()
                        except queue.Empty:
                            pass
                        self.file_paquets.put(donnees_brutes, block=False)
        except serial.SerialException as e:
            logger.error(f"Erreur de port série : {e}")
        finally:
            self._fermer_port_serie()

    def _traiter_paquets(self):
        try:
            while self.est_en_cours:
                try:
                    paquet = self.file_paquets.get(timeout=1)
                    metadonnees = self._extraire_metadonnees_paquet(paquet)
                    self.captures.append(metadonnees)
                except queue.Empty:
                    continue
        except Exception as e:
            logger.error(f"Erreur de traitement : {e}")

    def _extraire_metadonnees_paquet(self, paquet):
        try:
            donnees_analysees = analyser_paquet_zigbee(paquet)
            trame_decodee = decoder_trame_zigbee_complet(paquet)

            if trame_decodee and 'payload' in trame_decodee and 'hex' in trame_decodee['payload']:
                payload_hex = trame_decodee['payload']['hex']
                dechiffrement = decrypt_zigbee_payload(payload_hex, self.cle_dechiffrement)
                trame_decodee['payload']['dechiffre'] = dechiffrement

            return {
                'horodatage': datetime.now().isoformat(),
                'paquet_brut': paquet,
                'trame_decodee': trame_decodee,
                **donnees_analysees
            }
        except Exception as e:
            logger.error(f"Erreur d'analyse des métadonnées : {e}")
            return {'horodatage': datetime.now().isoformat(), 'paquet_brut': paquet}

    def sauvegarder_captures(self):
        try:
            with open(self.fichier_sortie, 'w', encoding='utf-8') as f:
                json.dump(self.captures, f, indent=2, ensure_ascii=False)
            logger.info(f"Captures sauvegardées dans {self.fichier_sortie}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des captures : {e}")

    def demarrer_sniffing(self, duree=60):
        self.est_en_cours = True
        self._configurer_sniffer()
        thread_capture = threading.Thread(target=self._capturer_paquets, daemon=True)
        thread_traitement = threading.Thread(target=self._traiter_paquets, daemon=True)
        thread_capture.start()
        thread_traitement.start()

        try:
            time.sleep(duree)
        except KeyboardInterrupt:
            logger.info("Interruption détectée. Arrêt en cours...")
        finally:
            self.est_en_cours = False
            thread_capture.join(timeout=2)
            thread_traitement.join(timeout=2)
            self.sauvegarder_captures()

def main():
    try:
        sniffeur = SniffeurZigbee(canal=13)
        sniffeur.demarrer_sniffing()
    except KeyboardInterrupt:
        logger.info("Interruption détectée. Sortie...")
    except Exception as e:
        logger.error(f"Erreur fatale : {e}")

if __name__ == "__main__":
    main()
