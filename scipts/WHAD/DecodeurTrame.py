import json
import logging


class DecodeurTrameZigbee:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)

    def decoder_champ_controle_trame(self, controle_trame):
        """Décoder le champ de contrôle MAC."""
        return {
            'type_trame': controle_trame & 0x07,  # Bits 0-2
            'securite_activee': (controle_trame >> 3) & 0x01,  # Bit 3
            'trame_en_attente': (controle_trame >> 4) & 0x01,  # Bit 4
            'ack_requis': (controle_trame >> 5) & 0x01,  # Bit 5
            'compression_pan_id': (controle_trame >> 6) & 0x01,  # Bit 6
            'version_trame': (controle_trame >> 12) & 0x03,  # Bits 12-13
            'mode_adresse_dst': (controle_trame >> 10) & 0x03,  # Bits 10-11
            'mode_adresse_src': (controle_trame >> 14) & 0x03,  # Bits 14-15
        }

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
        print("\n--- Décodage de la couche Réseau ZigBee ---")
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
        
        # Adresses Destination et Extended Source
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
        print("\n--- Décodage de la couche Sécurité ZigBee ---")
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

    def decoder_trame_zigbee(self, octets_trame):
        if not octets_trame:
            return None

        print("\n=== Décodage de la trame Zigbee ===")
        couche_mac = self.decoder_couche_mac(octets_trame)
        offset = couche_mac['offset']

        couche_reseau = self.decoder_couche_reseau(octets_trame, offset)
        offset = couche_reseau['offset']

        security_header = self.decoder_security_header(octets_trame, offset)
        offset = security_header['offset']

        # Extraction du vrai payload après toutes les couches
        payload = octets_trame[offset:].hex()
        print(f"\nPayload extrait : {payload}")

        return {
            'type_trame': 'Data',
            'couche_mac': couche_mac,
            'couche_reseau': couche_reseau,
            'security_header': security_header,
            'payload': payload
        }



