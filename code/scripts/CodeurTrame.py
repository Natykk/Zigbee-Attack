"""
Codeur de trames ZigBee.
Ce module implémente un codeur pour les différentes couches de trames ZigBee.
"""
import logging

class CodeurTrameZigbee:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)

    def encoder_champ_controle_trame(self, champs):
        """
        Encode le champ de contrôle MAC en fonction des champs fournis.
        """
        frame_type = champs.get('frame_type', 0) & 0x07
        securite_activee = (champs.get('securite_activee', 0) & 0x01) << 3
        trame_en_attente = (champs.get('trame_en_attente', 0) & 0x01) << 4
        ack_requis = (champs.get('ack_requis', 1) & 0x01) << 5
        compression_pan_id = (champs.get('compression_pan_id', 1) & 0x01) << 6
        mode_adresse_dst = (champs.get('mode_adresse_dst', 2) & 0x03) << 10
        mode_adresse_src = (champs.get('mode_adresse_src', 2) & 0x03) << 14
        version_trame = (champs.get('version_trame', 0) & 0x03) << 12

        controle_trame = (
            frame_type |
            securite_activee |
            trame_en_attente |
            ack_requis |
            compression_pan_id |
            mode_adresse_dst |
            mode_adresse_src |
            version_trame
        )
        return controle_trame.to_bytes(2, byteorder='little')

    def encoder_champ_controle_reseau(self, champs):
        """
        Encode le champ de contrôle réseau d'une trame ZigBee.
        """
        frame_type = champs.get('frame_type', 0) & 0x03
        protocol_version = (champs.get('protocol_version', 2) & 0x0F) << 2
        discover_route = (champs.get('discover_route', 1) & 0x03) << 6
        multicast = (champs.get('multicast', 0) & 0x01) << 8
        security = (champs.get('security', 1) & 0x01) << 9
        source_route = (champs.get('source_route', 0) & 0x01) << 10
        destination = (champs.get('destination', 1) & 0x01) << 11
        extended_source_present = 1 << 12 if champs.get('extended_source') else 0
        end_device = (champs.get('end_device', 0) & 0x01) << 13

        controle_reseau = (
            frame_type |
            protocol_version |
            discover_route |
            multicast |
            security |
            source_route |
            destination |
            extended_source_present |
            end_device
        )
        return controle_reseau.to_bytes(2, byteorder='little')

    def encoder_security_header(self, champs):
        """
        Encode l'en-tête de sécurité d'une trame ZigBee.
        """
        # Construction du security control field
        security_level = int(champs['Security_control_field']['Security_level'], 2)
        key_id_mode = int(champs['Security_control_field']['Key_id_mode'], 2) << 3
        extended_nonce = int(champs['Security_control_field']['extended_nonce']) << 5

        security_control = security_level | key_id_mode | extended_nonce
        security_control_bytes = security_control.to_bytes(1, byteorder='little')

        # Frame counter en little endian
        frame_counter = champs['frame_counter'].to_bytes(4, byteorder='little')
        
        # Extended source et key sequence number
        extended_source = bytes.fromhex(champs['extended_source'])
        key_sequence_number = bytes.fromhex(champs['key_sequence_number'])

        return (
            security_control_bytes +
            frame_counter +
            extended_source +
            key_sequence_number
        )

    def encoder_trame_data(self, champs):
        """
        Encode une trame de données ZigBee complète.
        """
        # Encodage de la couche MAC
        couche_mac = (
            self.encoder_champ_controle_trame(champs['couche_mac']['controle_trame']) +
            champs['couche_mac']['numero_sequence'].to_bytes(1, 'little') +
            bytes.fromhex(champs['couche_mac']['pan_id_destination']) +
            bytes.fromhex(champs['couche_mac']['adresse_destination']) +
            bytes.fromhex(champs['couche_mac']['adresse_source'])
        )

        # Encodage de la couche réseau
        couche_reseau = (
            self.encoder_champ_controle_reseau(champs['couche_reseau']['champ_controle_reseau']) +
            bytes.fromhex(champs['couche_reseau']['addr_dest']) +
            bytes.fromhex(champs['couche_reseau']['addr_src']) +
            champs['couche_reseau']['radius'].to_bytes(1, 'little') +
            champs['couche_reseau']['sequence_number'].to_bytes(1, 'little') +
            bytes.fromhex(champs['couche_reseau']['adresse_destination']) +
            bytes.fromhex(champs['couche_reseau']['extended_source'])
        )

        # Encodage du security header
        try : 
            security_header = self.encoder_security_header(champs['security_header'])
        
            # Ajout des données chiffrées et du MIC
            data = bytes.fromhex(champs['security_header']['Data'])
            mic = bytes.fromhex(champs['security_header']['mic'])
            return couche_mac + couche_reseau + security_header + data + mic
        except:
            return couche_mac + couche_reseau 
        

    def encoder_trame_zigbee(self, champs):
        """
        Encode une trame ZigBee en fonction de son type.
        """
        type_trame = champs['type_trame']
        if type_trame == 'Data':
            return self.encoder_trame_data(champs)
        else:
            raise ValueError("Type de trame non supporté")
'''
champs = {
    "type_trame": "Data",
    "couche_mac": {
      "controle_trame": {
        "frame_type": 1,
        "securite_activee": 0,
        "trame_en_attente": 0,
        "ack_requis": 1,
        "compression_pan_id": 1,
        "version_trame": 0,
        "mode_adresse_dst": 2,
        "mode_adresse_src": 2
      },
      "numero_sequence": 208,
      "pan_id_destination": "7d90",
      "adresse_destination": "9cba",
      "adresse_source": "0000",
      "offset": 9
    },
    "couche_reseau": {
      "champ_controle_reseau": {
        "frame_type": 0,
        "protocol_version": 2,
        "discover_route": 1,
        "multicast": 0,
        "security": 1,
        "source_route": 0,
        "destination": 1,
        "extended_source": "9e2860feffbd4d74",
        "end_device": 0
      },
      "radius": 30,
      "sequence_number": 14,
      "adresse_destination": "a13260feffbd4d74",
      "extended_source": "9e2860feffbd4d74",
      "offset": 33,
      "addr_dest": "9cba",
      "addr_src": "0000"
    },
    "security_header": {
      "Security_control_field": {
        "Security_level": "000",
        "Key_id_mode": "01",
        "extended_nonce": "1"
      },
      "frame_counter": 1040,
      "extended_source": "9e2860feffbd4d74",
      "key_sequence_number": "00",
      "offset": 47,
      "mic": "0ceb175f",
      "Data": "1e16470acdb56e9fa06352",
      "mic_length": 4
    }
  }

codeur = CodeurTrameZigbee()
trame = codeur.encoder_trame_zigbee(champs)
print(trame.hex())
'''
# Exemple d'utilisation Trame ACK
'''
codeur = CodeurTrameZigbee()

champs = {
    'type_trame': 'Ack',
    'sequence_number': 44
}

trame = codeur.encoder_trame_zigbee(champs)

print(trame.hex())

'''


# Exemple d'utilisation Trame Command

'''

codeur = CodeurTrameZigbee()

champs = {
    'type_trame': 'Command',
    'sequence_number': 44,
    'pan_id': '1900',
    'destination': 'FFFF',
    'source': '0000',
    'command_id': 1
}

trame = codeur.encoder_trame_zigbee(champs)

print(trame.hex())

'''

'''
# Exemple d'utilisation Trame Data



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
    
