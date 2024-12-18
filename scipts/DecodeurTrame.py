import json
import logging


class DecodeurTrameZigbee:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)

    def decoder_champ_controle_trame(self, controle_trame):
        """Décoder le champ de contrôle MAC."""
        return {
            'frame_type': controle_trame & 0x07,  # Bits 0-2
            'securite_activee': (controle_trame >> 3) & 0x01,  # Bit 3
            'trame_en_attente': (controle_trame >> 4) & 0x01,  # Bit 4
            'ack_requis': (controle_trame >> 5) & 0x01,  # Bit 5
            'compression_pan_id': (controle_trame >> 6) & 0x01,  # Bit 6
            'version_trame': (controle_trame >> 12) & 0x03,  # Bits 12-13
            'mode_adresse_dst': (controle_trame >> 10) & 0x03,  # Bits 10-11
            'mode_adresse_src': (controle_trame >> 14) & 0x03,  # Bits 14-15
        }

    def decoder_trame_ack(self, octets_trame):
        """Décoder une trame ACK."""
        sequence_number = octets_trame[2]
        return {
            'type_trame': 'Ack',
            'sequence_number': sequence_number
        }

    def decoder_trame_command(self, octets_trame):
        """Décoder une trame de commande."""
        offset = 2
        sequence_number = octets_trame[offset]
        offset += 1

        pan_id = octets_trame[offset:offset + 2].hex()
        offset += 2

        destination = octets_trame[offset:offset + 2].hex()
        offset += 2

        source = octets_trame[offset:offset + 2].hex()
        offset += 2

        command_id = octets_trame[offset]  # Identifiant de commande
        offset += 1

        return {
            'type_trame': 'Command',
            'sequence_number': sequence_number,
            'pan_id': pan_id,
            'destination': destination,
            'source': source,
            'command_id': command_id
        }

    def decoder_trame_data(self, octets_trame):
        """Décoder une trame Data complète."""
        couche_mac = self.decoder_couche_mac(octets_trame)
        offset = couche_mac['offset']

        # Couche réseau et sécurité ZigBee
        couche_reseau = self.decoder_couche_reseau(octets_trame, offset)
        offset = couche_reseau['offset']

        security_header = self.decoder_security_header(octets_trame, offset)
        offset = security_header['offset']

        # Extraction du payload
        payload = octets_trame[offset:].hex()

        return {
            'type_trame': 'Data',
            'couche_mac': couche_mac,
            'couche_reseau': couche_reseau,
            'security_header': security_header,
            'payload': payload
        }

    def decoder_trame_zigbee(self, octets_trame):
        if not octets_trame:
            return None

        # Décoder le champ de contrôle MAC pour identifier le Frame Type
        champ_controle_trame = int.from_bytes(octets_trame[:2], 'little')
        controle_trame = self.decoder_champ_controle_trame(champ_controle_trame)
        frame_type = controle_trame['frame_type']

        # Rediriger vers le bon décodeur en fonction du type de trame
        if frame_type == 0x2:  # Trame ACK
            return self.decoder_trame_ack(octets_trame)
        elif frame_type == 0x3:  # Trame Command
            return self.decoder_trame_command(octets_trame)
        elif frame_type == 0x1:  # Trame Data
            return self.decoder_trame_data(octets_trame)
        else:
            return {'type_trame': 'Inconnu', 'details': octets_trame.hex()}

    def decoder_couche_mac(self, octets_trame_mac):
        """Décoder la couche MAC."""
        offset = 0
        champ_controle_trame = int.from_bytes(octets_trame_mac[offset:offset + 2], byteorder='little')
        controle_trame = self.decoder_champ_controle_trame(champ_controle_trame)
        offset += 2

        numero_sequence = octets_trame_mac[offset]
        offset += 1

        pan_id_destination = octets_trame_mac[offset:offset + 2].hex()
        offset += 2

        adresse_destination = octets_trame_mac[offset:offset + 2].hex()
        offset += 2

        adresse_source = octets_trame_mac[offset:offset + 2].hex()
        offset += 2

        return {
            'controle_trame': controle_trame,
            'numero_sequence': numero_sequence,
            'pan_id_destination': pan_id_destination,
            'adresse_destination': adresse_destination,
            'adresse_source': adresse_source,
            'offset': offset
        }

    def decoder_couche_reseau(self, octets_trame, offset):
        """Décoder la couche réseau ZigBee."""
        champ_controle_reseau = octets_trame[offset:offset + 2].hex()
        offset += 2

        addr_dest = octets_trame[offset:offset + 2].hex()
        offset += 2

        addr_src = octets_trame[offset:offset + 2].hex()
        offset += 2

        radius = octets_trame[offset]
        offset += 1

        sequence_number = octets_trame[offset]
        offset += 1

        adresse_destination = octets_trame[offset:offset + 8].hex()
        offset += 8
        extended_source = octets_trame[offset:offset + 8].hex()
        offset += 8

        return {
            'champ_controle_reseau': champ_controle_reseau,
            'radius': radius,
            'sequence_number': sequence_number,
            'adresse_destination': adresse_destination,
            'extended_source': extended_source,
            'offset': offset,
            'addr_dest': addr_dest,
            'addr_src': addr_src
        }

    def decoder_security_header(self, octets_trame, offset):
        """Décoder le ZigBee Security Header."""
        extended_nonce = hex(octets_trame[offset])
        offset += 1

        frame_counter = octets_trame[offset:offset + 4].hex()
        offset += 4

        extended_source = octets_trame[offset:offset + 8].hex()
        offset += 8

        key_sequence_number = octets_trame[offset]
        offset += 1

        return {
            'extended_nonce': extended_nonce,
            'frame_counter': frame_counter,
            'extended_source': extended_source,
            'key_sequence_number': key_sequence_number,
            'offset': offset
        }


# Tests
#trame_ack = bytes.fromhex("020030")
#trame_command = bytes.fromhex("63880500190000146e044bfc")
#trame_data = bytes.fromhex("6188300019146e0000481a146e00001e222f3c60feffbd4d749e2860feffbd4d7428247002009e2860feffbd4d74005ca080848585055c298eab1c1c9f41")

#decoder = DecodeurTrameZigbee()
#print(json.dumps(decoder.decoder_trame_zigbee(trame_ack), indent=2))
#print(json.dumps(decoder.decoder_trame_zigbee(trame_command), indent=2))
#print(json.dumps(decoder.decoder_trame_zigbee(trame_data), indent=2))
