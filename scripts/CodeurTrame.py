"""

Ce module fournit une classe pour encoder des trames ZigBee à partir de champs spécifiques.

Classes
-------
CodeurTrameZigbee : Classe pour encoder les différentes couches et types de trames ZigBee.
"""

import logging

class CodeurTrameZigbee:
    """
    Classe pour encoder différentes trames ZigBee (ACK, Command, Data).

    Attributes
    ----------
    logger : logging.Logger
        Instance de logger pour le débogage.
    """

    def __init__(self, logger=None):
        """
        Initialise une instance de CodeurTrameZigbee.

        Parameters
        ----------
        logger : logging.Logger, optional
            Logger pour les messages de débogage. Si None, un logger par défaut est utilisé.
        """
        self.logger = logger or logging.getLogger(__name__)

    def encoder_champ_controle_trame(self, champs):
        """
        Encode le champ de contrôle MAC en fonction des champs fournis.

        Parameters
        ----------
        champs : dict
            Dictionnaire contenant les champs nécessaires pour encoder le champ de contrôle MAC. 
            Les clés possibles incluent :
            - 'frame_type' (int)
            - 'securite_activee' (int)
            - 'trame_en_attente' (int)
            - 'ack_requis' (int)
            - 'compression_pan_id' (int)
            - 'version_trame' (int)
            - 'mode_adresse_dst' (int)
            - 'mode_adresse_src' (int)

        Returns
        -------
        bytes
            Le champ de contrôle MAC encodé sous forme de deux octets.
        """
        frame_type = champs.get('frame_type', 0x3) & 0x07  # Bits 0-2
        securite_activee = (champs.get('securite_activee', 0) & 0x01) << 3  # Bit 3
        trame_en_attente = (champs.get('trame_en_attente', 0) & 0x01) << 4  # Bit 4
        ack_requis = (champs.get('ack_requis', 1) & 0x01) << 5  # Bit 5
        compression_pan_id = (champs.get('compression_pan_id', 1) & 0x01) << 6  # Bit 6
        version_trame = (champs.get('version_trame', 0) & 0x03) << 12  # Bits 12-13
        mode_adresse_dst = (champs.get('mode_adresse_dst', 2) & 0x03) << 10  # Bits 10-11
        mode_adresse_src = (champs.get('mode_adresse_src', 2) & 0x03) << 14  # Bits 14-15

        controle_trame = (
            frame_type
            | securite_activee
            | trame_en_attente
            | ack_requis
            | compression_pan_id
            | version_trame
            | mode_adresse_dst
            | mode_adresse_src
        )
        return controle_trame.to_bytes(2, byteorder='little')

    def encoder_trame_ack(self, sequence_number):
        """
        Encode une trame ACK ZigBee.

        Parameters
        ----------
        sequence_number : int
            Numéro de séquence de la trame ACK.

        Returns
        -------
        bytes
            Trame ACK encodée.
        """
        controle_trame = self.encoder_champ_controle_trame({
            'frame_type': 0x2,  # ACK frame
            'securite_activee': 0,
            'trame_en_attente': 0,
            'ack_requis': 0,
            'compression_pan_id': 0,
            'version_trame': 0,
            'mode_adresse_dst': 0,
            'mode_adresse_src': 0
        })
        return controle_trame + sequence_number.to_bytes(1, 'little')

    def encoder_trame_command(self, champs):
        """
        Encode une trame de commande ZigBee.

        Parameters
        ----------
        champs : dict
            Dictionnaire contenant les champs nécessaires pour encoder la trame de commande. 
            Les clés doivent inclure :
            - 'sequence_number' (int)
            - 'pan_id' (str)
            - 'destination' (str)
            - 'source' (str)
            - 'command_id' (int)

        Returns
        -------
        bytes
            Trame de commande encodée.
        """
        controle_trame = self.encoder_champ_controle_trame({
            'frame_type': 0x3,  # Command frame
            'securite_activee': 0,
            'trame_en_attente': 0,
            'ack_requis': 1,
            'compression_pan_id': 1,
            'version_trame': 0,
            'mode_adresse_dst': 2,
            'mode_adresse_src': 2
        })
        sequence_number = champs['sequence_number'].to_bytes(1, 'little')
        pan_id = bytes.fromhex(champs['pan_id'])
        destination = bytes.fromhex(champs['destination'])
        source = bytes.fromhex(champs['source'])
        command_id = champs['command_id'].to_bytes(1, 'little')
        return controle_trame + sequence_number + pan_id + destination + source + command_id

    def encoder_trame_data(self, champs):
        """
        Encode une trame de données ZigBee.

        Parameters
        ----------
        champs : dict
            Dictionnaire contenant les champs nécessaires pour encoder la trame de données. 
            Doit inclure les clés pour `couche_mac`, `couche_reseau`, `security_header`, et `payload`.

        Returns
        -------
        bytes
            Trame de données encodée.
        """
        couche_mac = self.encoder_couche_mac(champs['couche_mac'])
        couche_reseau = self.encoder_couche_reseau(champs['couche_reseau'])
        security_header = self.encoder_security_header(champs['security_header'])
        payload = bytes.fromhex(champs['payload'])
        return couche_mac + couche_reseau + security_header + payload

    def encoder_couche_mac(self, champs):
        """
        Encoder la couche MAC ZigBee.

        Parameters
        ----------
        champs : dict
            Dictionnaire contenant les champs nécessaires pour encoder la couche MAC. 
            Les clés doivent inclure :
            - 'controle_trame' (dict)
            - 'numero_sequence' (int)
            - 'pan_id_destination' (str)
            - 'adresse_destination' (str)
            - 'adresse_source' (str)

        Returns
        -------
        bytes
            La couche MAC encodée.
        """
        controle_trame = self.encoder_champ_controle_trame(champs['controle_trame'])
        numero_sequence = champs['numero_sequence'].to_bytes(1, 'little')
        pan_id_destination = bytes.fromhex(champs['pan_id_destination'])
        adresse_destination = bytes.fromhex(champs['adresse_destination'])
        adresse_source = bytes.fromhex(champs['adresse_source'])
        return controle_trame + numero_sequence + pan_id_destination + adresse_destination + adresse_source


    def encoder_couche_reseau(self, champs):
        """Encoder la couche réseau ZigBee.

        Parameters
        ----------
        champs : dict
            Dictionnaire contenant les champs nécessaires pour encoder la couche réseau. 
            Les clés doivent inclure :
            - 'champ_controle_reseau' (str)
            - 'addr_dest' (str)
            - 'addr_src' (str)
            - 'radius' (int)
            - 'sequence_number' (int)
            - 'adresse_destination' (str)
            - 'extended_source' (str)

        Returns
        -------

        bytes
            La couche réseau encodée.
        """
        champ_controle_reseau = bytes.fromhex(champs['champ_controle_reseau'])
        addr_dest = bytes.fromhex(champs['addr_dest'])
        addr_src = bytes.fromhex(champs['addr_src'])
        radius = champs['radius'].to_bytes(1, 'little')
        sequence_number = champs['sequence_number'].to_bytes(1, 'little')
        adresse_destination = bytes.fromhex(champs['adresse_destination'])
        extended_source = bytes.fromhex(champs['extended_source'])
        return champ_controle_reseau + addr_dest + addr_src + radius + sequence_number + adresse_destination + extended_source

    def encoder_security_header(self, champs):
        """Encoder le ZigBee Security Header.

        Parameters
        ----------

        champs : dict
            Dictionnaire contenant les champs nécessaires pour encoder le Security Header. 
            Les clés doivent inclure :
            - 'extended_nonce' (str)
            - 'frame_counter' (str)
            - 'extended_source' (str)
            - 'key_sequence_number' (int)

        Returns
        -------
        bytes
            Le Security Header encodé.

        """
        extended_nonce = int(champs['extended_nonce'], 16).to_bytes(1, 'little')
        frame_counter = bytes.fromhex(champs['frame_counter'])
        extended_source = bytes.fromhex(champs['extended_source'])
        key_sequence_number = champs['key_sequence_number'].to_bytes(1, 'little')
        return extended_nonce + frame_counter + extended_source + key_sequence_number

    def encoder_trame_zigbee(self, champs):
        """Encoder une trame ZigBee en fonction des champs donnés.

        Parameters
        ----------

        champs : dict
            Dictionnaire contenant les champs nécessaires pour encoder la trame ZigBee. 
            Les clés possibles dépendent du type de trame (Ack, Command, Data).

        Returns
        -------
        bytes
            Trame ZigBee encodée.
        """
        type_trame = champs['type_trame']
        if type_trame == 'Ack':
            return self.encoder_trame_ack(champs['sequence_number'])
        elif type_trame == 'Command':
            return self.encoder_trame_command(champs)
        elif type_trame == 'Data':
            return self.encoder_trame_data(champs)
        else:
            raise ValueError("Type de trame inconnu pour l'encodage.")


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
    