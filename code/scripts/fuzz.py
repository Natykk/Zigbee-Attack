import logging
import serial
from boofuzz import Session, Target, s_initialize, s_block_start, s_block_end, s_bytes, s_get, FuzzLoggerCsv, s_byte
from generateur_payload import ZigBeeHAZCLOnOffPayloadGenerator

# Configurer le logger (inchangé)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

class ZigbeeSerialConnection:
    """Connexion série pour envoyer les trames Zigbee."""
    def __init__(self, port="/dev/ttyUSB0", baudrate=115200, timeout=1):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser = None
        self.info = f"ZigbeeSerialConnection: {port} @ {baudrate}bps"
        self.open()
        # Envoyer le mode TX dès l'ouverture
        self.send(b"#CMD#MODE_TX")
        response = self.recv()
        logging.info("Réponse initiale: %s", response.hex() if response else "Aucune réponse")

    def open(self):
        try:
            if not self.ser or not self.ser.is_open:
                self.ser = serial.Serial(self.port, baudrate=self.baudrate, timeout=self.timeout)
                logging.info("Connexion ouverte sur %s", self.port)
        except serial.SerialException as e:
            logging.error("Erreur d'ouverture du port série: %s", e)
            raise

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()
            logging.info("Connexion fermée sur %s", self.port)

    def send(self, data):
        try:
            logging.info("Envoi des données : %s", data.hex())
            self.ser.write(data)
            self.ser.flush()
        except serial.SerialException as e:
            logging.error("Erreur lors de l'envoi: %s", e)

    def recv(self, bufsize=1024):
        try:
            return self.ser.read(bufsize)
        except serial.SerialException as e:
            logging.error("Erreur lors de la réception: %s", e)
            return b""



def define_zigbee_off_light():
    s_initialize("zigbee_off_light")
    s_block_start("zigbee_header")
    s_bytes(b"\x61\x61\x88\x24\xef\xf4\x3b\xd2\x00\x00\x48\x18\x3b\xd2\x00\x00", fuzzable=False)
    s_bytes(b"\x1e", fuzzable=False)
    s_bytes(b"\xb2\xa1\x32\x60\xfe\xff\xbd\x4d\x74\x2f\x3c\x60\xfe\xff\xbd\x4d\x74", fuzzable=False)
    s_block_end("zigbee_header")
    s_block_start("zigbee_payload")
    s_bytes(b"\x40\x0a\x06\x00\x04\x01\x01", fuzzable=False)
    # Commande fuzzable avec toutes les valeurs possibles
    s_byte(0x00, fuzzable=True, fuzz_values=[0x00, 0x01, 0x02, 0xFF, 0x10, 0x7F])
    s_block_end("zigbee_payload")
    return s_get("zigbee_off_light")

def define_zigbee_on_off_switch():
    s_initialize("zigbee_on_off_switch")
    s_block_start("zigbee_header")
    s_bytes(b"\x61\x61\x88\xAA\xef\xf4\x3b\xd2\x00\x00\x48\x18\x3b\xd2\x00\x00", fuzzable=False)
    s_bytes(b"\x1e", fuzzable=False)
    s_bytes(b"\xC0\xa1\x32\x60\xfe\xff\xbd\x4d\x74\x2f\x3c\x60\xfe\xff\xbd\x4d\x74", fuzzable=False)
    s_block_end("zigbee_header")
    s_block_start("zigbee_payload")
    s_bytes(b"\x40\x0a\x06\x00\x04\x01\x01", fuzzable=False)
    # Commande fuzzable avec toutes les valeurs possibles
    s_byte(0x01, fuzzable=True, fuzz_values=[0x00, 0x01, 0x02, 0xFF, 0x10, 0x7F])
    s_block_end("zigbee_payload")
    return s_get("zigbee_on_off_switch")

def main():
    zigbee_conn = ZigbeeSerialConnection(port="/dev/ttyUSB0", baudrate=115200)
    generator = ZigBeeHAZCLOnOffPayloadGenerator()
    try:
        target = Target(connection=zigbee_conn)
        with open('boofuzz-results.csv', 'w') as csv_file:
            session = Session(
                target=target,
                sleep_time=1,
                fuzz_loggers=[FuzzLoggerCsv(file_handle=csv_file)],
                web_port=26000
            )
            web_url = f"http://localhost:{session.web_port}"
            logging.info("Interface Web disponible sur %s", web_url)

            print("Connexion aux cibles...")
            session.connect(define_zigbee_off_light())
            print("Connexion aux cibles...")
            session.connect(define_zigbee_on_off_switch())

            # Ajout des payloads générés comme nouveaux cas de test
            anomaly_payloads = generator.generate_anomaly_payloads(num_payloads=50)
            for idx, payload in enumerate(anomaly_payloads):
                case_name = f"anomaly_{idx}"
                s_initialize(case_name)
                s_bytes(payload, fuzzable=True)  # Fuzzing sur l'ensemble du payload
                session.connect(s_get(case_name))

            session.fuzz()
    except Exception as e:
        logging.error("Erreur dans le fuzzing: %s", e)
    finally:
        if zigbee_conn:
            zigbee_conn.close()

if __name__ == "__main__":
    main()