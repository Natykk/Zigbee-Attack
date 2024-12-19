"""
Ce Module implémente un décodeur de trames ZigBee.
"""
import json
import logging


class DecodeurTrameZigbee:
    """
    @class DecodeurTrameZigbee
    @brief Classe pour décoder des trames ZigBee.
    @details Cette classe fournit des méthodes pour décoder différents types de trames ZigBee, telles que les trames ACK,
             les trames de commande et les trames de données. Elle extrait et structure les informations contenues dans
             les trames afin de faciliter leur analyse et leur traitement.
    """

    def __init__(self, logger=None):
        """
        @brief Constructeur de la classe DecodeurTrameZigbee.
        
        @param logger: Objet logger pour la journalisation des erreurs et des informations. Si aucun logger n'est fourni,
                       un logger par défaut est utilisé.
        """
        self.logger = logger or logging.getLogger(__name__)

    def decoder_champ_controle_trame(self, controle_trame):
        """
        @brief Décoder le champ de contrôle MAC d'une trame ZigBee.
        
        @param controle_trame: Champ de contrôle MAC sous forme d'entier, représentant les premiers octets du champ de contrôle.
        
        @return: Un dictionnaire contenant les différents champs du contrôle de trame décodés :
                 - frame_type: Type de la trame
                 - securite_activee: Indicateur de sécurité
                 - trame_en_attente: Indicateur de trame en attente
                 - ack_requis: Indicateur d'ACK requis
                 - compression_pan_id: Indicateur de compression du PAN ID
                 - version_trame: Version de la trame
                 - mode_adresse_dst: Mode d'adresse de destination
                 - mode_adresse_src: Mode d'adresse source
        """
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
        """
        @brief Décoder une trame ACK ZigBee.
        
        @param octets_trame: Les octets de la trame ACK à décoder.
        
        @return: Un dictionnaire contenant les informations suivantes :
                 - type_trame: Type de la trame ('Ack')
                 - sequence_number: Numéro de séquence de la trame
        """
        sequence_number = octets_trame[2]
        return {
            'type_trame': 'Ack',
            'sequence_number': sequence_number
        }

    def decoder_trame_command(self, octets_trame):
        """
        @brief Décoder une trame de commande ZigBee.
        
        @param octets_trame: Les octets de la trame de commande à décoder.
        
        @return: Un dictionnaire contenant les informations suivantes :
                 - type_trame: Type de la trame ('Command')
                 - sequence_number: Numéro de séquence de la trame
                 - pan_id: PAN ID
                 - destination: Adresse de destination
                 - source: Adresse source
                 - command_id: Identifiant de la commande
        """
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
        """
        @brief Décoder une trame Data ZigBee complète.
        
        @param octets_trame: Les octets de la trame Data à décoder.
        
        @return: Un dictionnaire contenant les informations suivantes :
                 - type_trame: Type de la trame ('Data')
                 - couche_mac: Informations sur la couche MAC
                 - couche_reseau: Informations sur la couche réseau
                 - security_header: Informations sur l'en-tête de sécurité
                 - payload: Données utiles de la trame (payload)
        """
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
        """
        @brief Décoder une trame ZigBee en fonction du type de trame.
        
        @param octets_trame: Les octets de la trame ZigBee à décoder.
        
        @return: Un dictionnaire contenant les informations de la trame décodée, y compris le type de trame
                 (ACK, Command ou Data) et les détails associés. Si la trame est inconnue, retourne un dictionnaire
                 avec le type 'Inconnu'.
        """
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
        """
        @brief Décoder la couche MAC d'une trame ZigBee.
        
        @param octets_trame_mac: Les octets de la trame MAC à décoder.
        
        @return: Un dictionnaire contenant les informations suivantes :
                 - controle_trame: Champ de contrôle décodé
                 - numero_sequence: Numéro de séquence
                 - pan_id_destination: PAN ID de destination
                 - adresse_destination: Adresse de destination
                 - adresse_source: Adresse source
                 - offset: Décalage après la couche MAC
        """
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
        """
        @brief Décoder la couche réseau d'une trame ZigBee.
        
        @param octets_trame: Les octets de la trame à décoder.
        @param offset: Décalage après la couche MAC.
        
        @return: Un dictionnaire contenant les informations suivantes :
                 - champ_controle_reseau: Champ de contrôle réseau
                 - radius: Rayon de la trame
                 - sequence_number: Numéro de séquence
                 - adresse_destination: Adresse de destination
                 - extended_source: Source étendue
                 - offset: Décalage après la couche réseau
                 - addr_dest: Adresse de destination
                 - addr_src: Adresse source
        """
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
        """
        @brief Décoder l'en-tête de sécurité ZigBee.
        
        @param octets_trame: Les octets de la trame à décoder.
        @param offset: Décalage après la couche réseau.
        
        @return: Un dictionnaire contenant les informations suivantes :
                 - extended_nonce: Nonce étendu
                 - frame_counter: Compteur de trame
                 - extended_source: Source étendue
                 - key_sequence_number: Numéro de séquence de la clé
                 - offset: Décalage après l'en-tête de sécurité
        """
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
#trame_ack = bytes.fromhex("02002c")

#trame_command = bytes.fromhex("63884a00190000146e04")

#trame_data = bytes.fromhex("6188300019146e0000481a146e00001e222f3c60feffbd4d749e2860feffbd4d7428247002009e2860feffbd4d74005ca080848585055c298eab1c1c9f41")
#decoder = DecodeurTrameZigbee()
#print(json.dumps(decoder.decoder_trame_zigbee(trame_ack), indent=2))
#print(json.dumps(decoder.decoder_trame_zigbee(trame_command), indent=2))
#print(json.dumps(decoder.decoder_trame_zigbee(trame_data), indent=2))

#Ecriture dans un fichier
#with open('captures_zigbee.json', 'w') as f:
#    json.dump(decoder.decoder_trame_zigbee(trame_data), f, indent=2)
