"""
Décodeur de trames ZigBee.
Ce module implémente un décodeur pour analyser et interpréter différents types
de trames ZigBee.
"""
import json
import logging


class DecodeurTrameZigbee:
    """
    Classe pour décoder des trames ZigBee.

    Cette classe fournit des méthodes pour décoder différents types de trames ZigBee,
    telles que les trames ACK, les trames de commande et les trames de données.
    Elle extrait et structure les informations contenues dans les trames afin de
    faciliter leur analyse et leur traitement.
    """

    def __init__(self, logger=None):
        """
        Initialise le décodeur de trames ZigBee.

        Parameters
        ----------
        logger : logging.Logger, optional
            Objet logger pour la journalisation des erreurs et des informations.
            Si non fourni, un logger par défaut est utilisé.
        """
        self.logger = logger or logging.getLogger(__name__)

    def decoder_champ_controle_trame(self, controle_trame):
        """
        Décode le champ de contrôle MAC d'une trame ZigBee.

        Parameters
        ----------
        controle_trame : int
            Champ de contrôle MAC sous forme d'entier, représentant les premiers
            octets du champ de contrôle.

        Returns
        -------
        dict
            Dictionnaire contenant les différents champs du contrôle de trame décodés :
            - frame_type : Type de la trame
            - securite_activee : Indicateur de sécurité
            - trame_en_attente : Indicateur de trame en attente
            - ack_requis : Indicateur d'ACK requis
            - compression_pan_id : Indicateur de compression du PAN ID
            - version_trame : Version de la trame
            - mode_adresse_dst : Mode d'adresse de destination
            - mode_adresse_src : Mode d'adresse source
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
        Décode une trame ACK ZigBee.

        Parameters
        ----------
        octets_trame : bytes
            Les octets de la trame ACK à décoder.

        Returns
        -------
        dict
            Dictionnaire contenant les informations de la trame ACK :
            - type_trame : Type de la trame ('Ack')
            - sequence_number : Numéro de séquence de la trame
        """
        sequence_number = octets_trame[2]
        return {
            'type_trame': 'Ack',
            'sequence_number': sequence_number
        }

    def decoder_trame_command(self, octets_trame):
        """
        Décode une trame de commande ZigBee.

        Parameters
        ----------
        octets_trame : bytes
            Les octets de la trame de commande à décoder.

        Returns
        -------
        dict
            Dictionnaire contenant les informations de la trame de commande :
            - type_trame : Type de la trame ('Command')
            - sequence_number : Numéro de séquence de la trame
            - pan_id : PAN ID
            - destination : Adresse de destination
            - source : Adresse source
            - command_id : Identifiant de la commande
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
        command_id = octets_trame[offset]
        
        offset += 1

        return {
            'type_trame': 'Command',
            'sequence_number': sequence_number,
            'pan_id': pan_id,
            'destination': destination,
            'source': source,
            'command_id': command_id
        }
    
    def decoder_couche_aps(self, octets_trame, offset):

        frame_control_field = octets_trame[offset:offset+1]
        

        val = bin(int.from_bytes(frame_control_field, byteorder='little'))[2:].zfill(8)
        val = val[::-1]
 
        
        frame_type = int(val[0:2],2)

        delivery_mode = int(val[2:4],2)

        security = int(val[5],2)

        ack_request = int(val[6],2)

        extended_header = int(val[7],2)

        offset += 1

        destination_endpoint = int.from_bytes(octets_trame[offset:offset+1])

        offset += 1

        cluster_id = octets_trame[offset:offset+2].hex()


        offset += 2

        profile_id = octets_trame[offset:offset+2].hex()

        offset += 2

        source_endpoint = int.from_bytes(octets_trame[offset:offset+1])

        offset += 1

        counter = int.from_bytes(octets_trame[offset:offset+1])

        offset += 1

        return {

            'frame_control_field': {
                'frame_type': frame_type,
                'delivery_mode': delivery_mode,
                'security': security,
                'ack_request': ack_request,
                'extended_header': extended_header
            },
            'destination_endpoint': destination_endpoint,
            'cluster_id': cluster_id,
            'profile_id': profile_id,
            'source_endpoint': source_endpoint,
            'counter': counter,
            'offset': offset
        }
    

    def decoder_couche_zcl(self, octets_trame, offset):
        frame_control_field = octets_trame[offset:offset+1]
        val = bin(int.from_bytes(frame_control_field, byteorder='little'))[2:].zfill(8)

        val = val[::-1]

        frame_type = val[0:2]
        frame_type = frame_type[::-1]
        frame_type = int(frame_type,2)
   

        manufacturer_specific = int(val[2],2)
   

        direction = int(val[3],2)
        if direction == 0:
            direction = "Client to Server"
        else:
            direction = "Server to Client"
   

        disable_default_response = int(val[4],2)

        offset += 1

        Sequence_number = int.from_bytes(octets_trame[offset:offset+1])

        offset += 1

        command_id = octets_trame[offset:offset+1].hex()

        offset += 1

        return {
            'frame_control_field': {
                'frame_type': frame_type,
                'manufacturer_specific': manufacturer_specific,
                'direction': direction,
                'disable_default_response': disable_default_response
            },
            'Sequence_number': Sequence_number,
            'command_id': command_id,
            'offset': offset
        }
    
    


        

    def decoder_trame_data(self, octets_trame):
        """
        Décode une trame Data ZigBee complète.

        Parameters
        ----------
        octets_trame : bytes
            Les octets de la trame Data à décoder.

        Returns
        -------
        dict
            Dictionnaire contenant les informations de la trame Data :
            - type_trame : Type de la trame ('Data')
            - couche_mac : Informations sur la couche MAC
            - couche_reseau : Informations sur la couche réseau
            - security_header : Informations sur l'en-tête de sécurité
            - payload : Données utiles de la trame (payload)
        """
        couche_mac = self.decoder_couche_mac(octets_trame)
        offset = couche_mac['offset']

        couche_reseau = self.decoder_couche_reseau(octets_trame, offset)
        offset = couche_reseau['offset']
 
        if couche_reseau['champ_controle_reseau']['security']:
            #TODO: Déchiffrer le payload
            pass   
        else:
            decoder_couche_aps = self.decoder_couche_aps(octets_trame, offset)
            offset = decoder_couche_aps['offset']
            decoder_couche_zcl = self.decoder_couche_zcl(octets_trame, offset)
            offset = decoder_couche_zcl['offset']
            payload = octets_trame[offset:].hex()
            return {
                'type_trame': 'Data',
                'couche_mac': couche_mac,
                'couche_reseau': couche_reseau,
                'couche_aps': decoder_couche_aps,
                'couche_zcl': decoder_couche_zcl,
                'payload': payload
            }

    def decoder_trame_zigbee(self, octets_trame):
        """
        Décode une trame ZigBee en fonction de son type.

        Parameters
        ----------
        octets_trame : bytes
            Les octets de la trame ZigBee à décoder.

        Returns
        -------
        dict or None
            Dictionnaire contenant les informations de la trame décodée, incluant
            le type de trame (ACK, Command ou Data) et les détails associés.
            Retourne None si la trame est vide.
        """
        if not octets_trame:
            return None

        champ_controle_trame = int.from_bytes(octets_trame[:2], 'little')
        controle_trame = self.decoder_champ_controle_trame(champ_controle_trame)
        frame_type = controle_trame['frame_type']

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
        Décode la couche MAC d'une trame ZigBee.

        Parameters
        ----------
        octets_trame_mac : bytes
            Les octets de la trame MAC à décoder.

        Returns
        -------
        dict
            Dictionnaire contenant les informations de la couche MAC :
            - controle_trame : Champ de contrôle décodé
            - numero_sequence : Numéro de séquence
            - pan_id_destination : PAN ID de destination
            - adresse_destination : Adresse de destination
            - adresse_source : Adresse source
            - offset : Décalage après la couche MAC
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
        Décode la couche réseau d'une trame ZigBee.

        Parameters
        ----------
        octets_trame : bytes
            Les octets de la trame à décoder.
        offset : int
            Décalage après la couche MAC.

        Returns
        -------
        dict
            Dictionnaire contenant les informations de la couche réseau :
            - champ_controle_reseau : Champ de contrôle réseau
            - radius : Rayon de la trame
            - sequence_number : Numéro de séquence
            - adresse_destination : Adresse de destination
            - extended_source : Source étendue
            - offset : Décalage après la couche réseau
            - addr_dest : Adresse de destination
            - addr_src : Adresse source
        """
        champ_controle_reseau = octets_trame[offset:offset + 2]
        # Je prends les 2 premiers bits pour le champ de contrôle réseau
        val = bin(int.from_bytes(champ_controle_reseau, byteorder='little'))[2:].zfill(16)
        val = val[::-1]
        
        # Extraction des champs selon les positions de l'image
        frame_type = int(val[0:1],2)          # Bits 0-2
 
        protocol_version = val[2:6]  # Bits 3-6
        protocol_version = protocol_version[::-1]
        protocol_version = int(protocol_version,2)
        

        discover_route = int(val[5:7],2)      # Bits 5-6
     
        # Flags individuels
        multicast = int(val[7],2)            # Bit 7
     
        security = int(val[9],2)             # Bit 8
     

        source_route = int(val[10],2)         # Bit 9
     
        
        destination = int(val[-5],2)         # Bit 10 (valeur différente de l'image)
   
        
        extended_source = int(val[-4],2)     # Bit 11
     
        
        end_device = int(val[-3],2)
        
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
            'champ_controle_reseau': {
                'frame_type': frame_type,
                'protocol_version': protocol_version,
                'discover_route': bool(discover_route),
                'multicast': bool(multicast),
                'security': bool(security),
                'source_route': bool(source_route),
                'destination': bool(destination),
                'extended_source': bool(extended_source),
                'end_device': bool(end_device)
            },
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
        Décode l'en-tête de sécurité ZigBee.

        Parameters
        ----------
        octets_trame : bytes
            Les octets de la trame à décoder.
        offset : int
            Décalage après la couche réseau.

        Returns
        -------
        dict
            Dictionnaire contenant les informations de l'en-tête de sécurité :
            - extended_nonce : Nonce étendu
            - frame_counter : Compteur de trame
            - extended_source : Source étendue
            - key_sequence_number : Numéro de séquence de la clé
            - offset : Décalage après l'en-tête de sécurité
        """
        print(octets_trame[offset:offset+1].hex())

        Security_control_field = octets_trame[offset:offset+1]

        val = bin(int.from_bytes(Security_control_field, byteorder='little'))[2:].zfill(8)
        val = val[::-1]

        Security_level = val[0:3]
     
        Key_id_mode = val[3:5]
        Key_id_mode = Key_id_mode[::-1]
        extended_nonce = val[5]
        
        offset += 1

        frame_counter = octets_trame[offset:offset + 4].hex()
        #Convertir en big endian
        frame_counter = frame_counter[6:8] + frame_counter[4:6] + frame_counter[2:4] + frame_counter[0:2]
        frame_counter = int(frame_counter, 16)
        
        offset += 4

        extended_source = octets_trame[offset:offset + 8].hex()

        offset += 8

        key_sequence_number = octets_trame[offset:offset + 1].hex()
    
        offset += 1
        Data = octets_trame[offset:-4].hex()
        

        mic = octets_trame[-4:].hex()


        mic_length = len(mic) // 2

        return {
            'Security_control_field': {
                'Security_level': Security_level,
                'Key_id_mode': Key_id_mode,
                'extended_nonce': extended_nonce
            },
            'frame_counter': frame_counter,
            'extended_source': extended_source,
            'key_sequence_number': key_sequence_number,
            'offset': offset,
            'mic': mic,
            'Data': Data,
            'mic_length': mic_length
        }

