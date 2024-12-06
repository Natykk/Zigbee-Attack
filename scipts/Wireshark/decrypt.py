from Crypto.Cipher import AES
from Crypto.Util import Counter

# Fonction pour le padding
def pad(data, block_size=16):
    pad_len = (block_size - len(data) % block_size) % block_size
    return data + bytes([0] * pad_len)

# Fonction pour afficher les données en hexadécimal
def printhex(data):
    print(" ".join(f"{byte:02X}" for byte in data))

# Définir les variables
key = bytes([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
])  # Nouvelle clé

nonce = bytes([0x74, 0x4D, 0xBD, 0xFF, 0xFE, 0x60, 0x28, 0x9E, 0x10, 0xE4, 0x00, 0x00, 0x28])
AddAuthData = bytes([0x02, 0x15, 0x16])  # Données supplémentaires d'authentification
Flags = bytes([0x49])  # Champ de drapeaux du protocole CCM
message_chiffre = bytes([0xBD, 0xCA, 0x72, 0x94, 0x1C, 0x91, 0xCB, 0x9E, 0x9F, 0xA9, 0xCF])  # Charge utile chiffrée
expected_MIC = bytes([0xAC, 0x4C, 0x76, 0xAF])  # MIC reçu avec le message

# Générer le B0 pour le MIC
m = message_chiffre  # Message chiffré
B0 = Flags + nonce + len(m).to_bytes(2, byteorder="big")

# Étape 1 : Vérification du MIC
def verify_mic(key, B0, AddAuthData, m, expected_MIC):
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes([0] * 16))
    X1 = cipher.encrypt(B0 + pad(AddAuthData) + pad(m))
    calculated_MIC = X1[-16:-12]
    return calculated_MIC == expected_MIC

mic_valid = verify_mic(key, B0, AddAuthData, m, expected_MIC)
if mic_valid:
    print("Le MIC est valide.")
else:
    print("Le MIC est invalide. Le message a peut-être été modifié.")
    exit(1)

# Étape 2 : Déchiffrement de la charge utile
def decrypt_payload(key, nonce, ciphertext):
    ctr = Counter.new(64, prefix=nonce, initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)

# Déchiffrement
plaintext = decrypt_payload(key, nonce, message_chiffre)

# Afficher la charge utile déchiffrée
print("Charge utile déchiffrée :")
printhex(plaintext)
