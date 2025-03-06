import random
import struct
from typing import List

class ZigBeeHAZCLOnOffPayloadGenerator:
    """
    Générateur de payloads ZigBee Home Automation On/Off 
    """
    def __init__(self):

        self.config = {
            'ieee_frame_control': [0x8861, 0x8860, 0x8863],
            'nwk_frame_control': [0x1848, 0x1840, 0x1849],
            'aps_frame_control': [0x40, 0x44, 0x41],
            'zcl_frame_control': [0x01, 0x00, 0x11],
            
            'endpoints': {
                'source': [1],
                'destination': [10]
            },
            
            'clusters': {
                'On/Off': 0x0006
            },
            
            'commands': {
                'Off': 0x00,
                'On': 0x01,
                'Toggle': 0x02,
                'Invalid': [0xFF, 0x10, 0x7F]
            }
        }

    def generate_zigbee_payload(self) -> bytes:
        """
        Génère un payload ZigBee On/Off complet
        """
        # Structure de base du payload basée sur la trace Wireshark
        payload = bytearray()
        
        # IEEE 802.15.4 Frame
        payload.extend(struct.pack('>H', random.choice(self.config['ieee_frame_control'])))  # Frame Control
        payload.extend(struct.pack('B', random.randint(0, 255)))  # Sequence Number
        payload.extend(struct.pack('>H', random.randint(0, 0xFFFF)))  # Destination PAN
        payload.extend(struct.pack('>H', random.randint(0, 0xFFFF)))  # Destination Address
        payload.extend(struct.pack('>H', random.randint(0, 0xFFFF)))  # Source Address
        
        # Network Layer
        payload.extend(struct.pack('>H', random.choice(self.config['nwk_frame_control'])))  # Frame Control
        payload.extend(struct.pack('>H', random.randint(0, 0xFFFF)))  # Destination
        payload.extend(struct.pack('>H', random.randint(0, 0xFFFF)))  # Source
        payload.extend(struct.pack('B', random.randint(1, 30)))  # Radius
        payload.extend(struct.pack('B', random.randint(0, 255)))  # Sequence Number
        
        # APS Layer
        payload.extend(struct.pack('B', random.choice(self.config['aps_frame_control'])))  # Frame Control
        payload.extend(struct.pack('B', random.choice(self.config['endpoints']['destination'])))  # Destination Endpoint
        payload.extend(struct.pack('>H', self.config['clusters']['On/Off']))  # Cluster
        payload.extend(struct.pack('>H', 0x0104))  # Profile (Home Automation)
        payload.extend(struct.pack('B', random.choice(self.config['endpoints']['source'])))  # Source Endpoint
        payload.extend(struct.pack('B', random.randint(0, 255)))  # Counter
        
        # ZCL Frame
        payload.extend(struct.pack('B', random.choice(self.config['zcl_frame_control'])))  # Frame Control
        payload.extend(struct.pack('B', random.randint(0, 255)))  # Sequence Number
        
        # Correction ici :
        command_bytes = []
        for cmd in self.config['commands'].values():
            if isinstance(cmd, list):
                command_bytes.extend(cmd)
            else:
                command_bytes.append(cmd)
        payload.extend(struct.pack('B', random.choice(command_bytes)))  # Command
    

        return bytes(payload)

    def generate_anomaly_payloads(self, num_payloads=50) -> List[bytes]:
        """
        Génère des payloads avec des anomalies potentielles
        """
        return [self._mutate_payload(self.generate_zigbee_payload()) for _ in range(num_payloads)]

    def _mutate_payload(self, payload: bytes) -> bytes:
        """
        Applique des mutations sur le payload
        """
        mutation_strategies = [
            self._bit_flip,
            self._random_byte_replace,
            self._extreme_value_injection
        ]
        
        strategy = random.choice(mutation_strategies)
        return strategy(payload)

    def _bit_flip(self, payload: bytes) -> bytes:
        """Stratégie de mutation : bit flipping"""
        payload_list = bytearray(payload)
        index = random.randint(0, len(payload_list) - 1)
        payload_list[index] ^= (1 << random.randint(0, 7))
        return bytes(payload_list)

    def _random_byte_replace(self, payload: bytes) -> bytes:
        """Stratégie de mutation : remplacement aléatoire d'octets"""
        payload_list = bytearray(payload)
        index = random.randint(0, len(payload_list) - 1)
        payload_list[index] = random.randint(0, 255)
        return bytes(payload_list)

    def _extreme_value_injection(self, payload: bytes) -> bytes:
        """Stratégie de mutation : injection de valeurs extrêmes"""
        payload_list = bytearray(payload)
        extreme_values = [0x00, 0xFF, 0x7F, 0x80]
        index = random.randint(0, len(payload_list) - 1)
        payload_list[index] = random.choice(extreme_values)
        return bytes(payload_list)
    
