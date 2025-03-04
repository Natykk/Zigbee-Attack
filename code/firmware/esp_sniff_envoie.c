/**
 * @file esp_sniff_envoie_cli.c
 * @brief Firmware pour ESP32H2 permettant la capture (sniffing) et la transmission de trames IEEE 802.15.4 (ZigBee)
 *
 * Ce firmware implémente deux modes de fonctionnement:
 * - MODE_SNIFF: Capture en mode promiscuité toutes les trames IEEE 802.15.4 sur un canal spécifié
 * - MODE_TX: Permet d'envoyer des trames IEEE 802.15.4 reçues via UART
 * 
 * La communication avec l'hôte se fait via UART. Les trames capturées sont envoyées dans un format
 * spécifique: [séquence|RSSI: valeurDB| tailleB] trameHEX
 * Des commandes peuvent être envoyées au ESP32H2 via UART en utilisant le préfixe "#CMD#".
 */

 #include <stdio.h>
 #include <string.h>
 #include "esp_system.h"
 #include "esp_log.h"
 #include "esp_ieee802154.h"    // API IEEE 802.15.4 de l'ESP-IDF
 #include "nvs_flash.h"         // Stockage non-volatile
 #include "driver/uart.h"       // API UART 
 #include "freertos/queue.h"    // Files d'attente FreeRTOS
 #include "esp_attr.h"          // Attributs spéciaux ESP32
 
 // Constantes de configuration
 #define TAG "IEEE802154_MODE"  // Tag pour les messages de log
 #define UART_PORT_NUM UART_NUM_0       // Port UART utilisé (UART0 = port série par défaut)
 #define UART_BAUD_RATE 115200          // Vitesse de communication UART en bauds
 #define BUF_SIZE 2048                  // Taille du buffer UART en octets
 #define MAX_FRAME_SIZE 127             // Taille maximale d'une trame IEEE 802.15.4 (127 octets)
 #define CMD_PREFIX "#CMD#"             // Préfixe pour les commandes reçues via UART
 #define CMD_PREFIX_LEN 5               // Longueur du préfixe de commande
 #define CHANNEL 13                     // Canal IEEE 802.15.4 par défaut (13 = 2415 MHz)
 #define QUEUE_SIZE 40                  // Taille de la file d'attente pour les trames capturées
 
 /**
  * @brief Modes d'opération du firmware
  */
 typedef enum {
     MODE_SNIFF,    // Mode de capture de trames
     MODE_TX        // Mode de transmission de trames
 } operation_mode_t;
 
 // Variables globales
 static QueueHandle_t rx_queue = NULL;                // File d'attente pour les paquets reçus
 static volatile operation_mode_t current_mode = MODE_TX;  // Mode de fonctionnement actuel
 static uint32_t dropped_packets = 0;                // Compteur de paquets perdus (file pleine)
 
 /**
  * @brief Structure pour stocker un paquet capturé avec ses métadonnées
  */
 typedef struct {
     uint8_t data[MAX_FRAME_SIZE + 1];  // Données brutes de la trame (+1 pour la longueur)
     uint8_t len;                       // Longueur de la trame
     int8_t rssi;                       // Puissance du signal reçu en dBm
 } rx_packet_t;
 
 /**
  * @brief Initialise le stockage non-volatile (NVS)
  * 
  * Cette fonction est nécessaire pour le fonctionnement de l'ESP-IDF
  * et prépare la flash pour le stockage de paramètres persistants.
  */
 static void initialize_nvs(void) {
     esp_err_t err = nvs_flash_init();
     // Si la partition NVS est corrompue ou d'une version incompatible,
     // on l'efface et on réinitialise
     if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
         ESP_ERROR_CHECK(nvs_flash_erase());
         err = nvs_flash_init();
     }
     ESP_ERROR_CHECK(err);
 }
 
 /**
  * @brief Change le mode de fonctionnement du firmware
  * 
  * Configure la radio IEEE 802.15.4 selon le mode demandé:
  * - MODE_SNIFF: Active le mode promiscuité, définit l'adresse et PAN ID à 0xFFFF
  * - MODE_TX: Désactive la réception en continu pour permettre la transmission
  * 
  * @param new_mode Nouveau mode à activer (MODE_SNIFF ou MODE_TX)
  */
 void switch_mode(operation_mode_t new_mode) {
     if (current_mode == new_mode) return;  // Ne rien faire si on est déjà dans ce mode
 
     current_mode = new_mode;  // Met à jour le mode courant
 
     if (new_mode == MODE_SNIFF) {
         // Configuration pour le mode de capture:
         // - Mode promiscuité: capture toutes les trames sans filtrage
         // - PAN ID et adresse à 0xFFFF: accepte toutes les trames
         // - RX when idle: écoute en continu
         ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(true));
         ESP_ERROR_CHECK(esp_ieee802154_set_panid(0xFFFF));
         ESP_ERROR_CHECK(esp_ieee802154_set_short_address(0xFFFF));
         ESP_ERROR_CHECK(esp_ieee802154_set_rx_when_idle(true));
         ESP_ERROR_CHECK(esp_ieee802154_receive());  // Démarre la réception
         ESP_LOGI(TAG, "Mode SNIFF activé (Canal %d)", CHANNEL);
     } else {
         // Configuration pour le mode de transmission:
         // - Désactive le mode promiscuité
         // - Désactive la réception en continu
         ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(false));
         ESP_ERROR_CHECK(esp_ieee802154_set_rx_when_idle(false));
         ESP_LOGI(TAG, "Mode TX activé");
     }
 }
 
 // Buffer pour stocker les données reçues par l'UART
 static uint8_t uart_data_buffer[BUF_SIZE];
 
 /**
  * @brief Callback appelé par l'API IEEE 802.15.4 quand une trame est reçue
  * 
  * Cette fonction est exécutée dans le contexte d'une interruption (ISR).
  * Elle crée un nouveau paquet, y copie les données de la trame et les métadonnées,
  * puis l'envoie dans la file d'attente pour traitement ultérieur.
  * 
  * @param frame Pointeur vers les données de la trame reçue
  * @param frame_info Structure contenant les métadonnées de la trame (RSSI, etc.)
  */
 IRAM_ATTR void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
     if (current_mode != MODE_SNIFF) return;  // Ignorer si pas en mode SNIFF
 
     // Allouer de la mémoire pour le paquet
     rx_packet_t *packet = malloc(sizeof(rx_packet_t));
     if (!packet) {
         // En cas d'échec d'allocation mémoire, incrémenter le compteur de paquets perdus
         dropped_packets++;
         esp_ieee802154_receive();  // Redémarrer la réception
         return;
     }
 
     // Copie des données et métadonnées
     packet->len = frame[0] + 1;  // La longueur est dans le premier octet + 1 pour inclure cet octet
     packet->rssi = frame_info->rssi;  // Force du signal reçu
     memcpy(packet->data, frame, packet->len);
 
     // Variable pour indiquer si une tâche de priorité plus élevée doit être réveillée
     BaseType_t xHigherPriorityTaskWoken = pdFALSE;
     
     // Envoi du paquet dans la file d'attente
     if (xQueueSendFromISR(rx_queue, &packet, &xHigherPriorityTaskWoken) != pdTRUE) {
         // Si la file est pleine, libérer la mémoire et incrémenter le compteur
         free(packet);
         dropped_packets++;
     }
 
     // Notifier que le traitement de la trame est terminé
     esp_ieee802154_receive_handle_done(frame);
     // Redémarrer la réception pour la trame suivante
     esp_ieee802154_receive();
 
     // Si une tâche de priorité plus élevée a été réveillée, demander un changement de contexte
     if (xHigherPriorityTaskWoken) {
         portYIELD_FROM_ISR();
     }
 }
 
 /**
  * @brief Tâche FreeRTOS qui envoie les paquets capturés via UART
  * 
  * Cette tâche attend des paquets dans la file d'attente rx_queue,
  * les formate selon le format [séquence|RSSI: valeurDB| tailleB] trameHEX
  * et les envoie sur le port UART.
  * 
  * @param pvParameters Paramètres de la tâche (non utilisés)
  */
 static void uart_send_task(void *pvParameters) {
     rx_packet_t *packet;
     // Buffer pour construire la chaîne de sortie
     // Doit être placé en DRAM pour des performances optimales
     static DRAM_ATTR char output_buffer[MAX_FRAME_SIZE * 3 + 50]; 
     // Mutex pour protéger l'accès à l'UART
     static SemaphoreHandle_t uart_mutex = NULL;
     
     if(uart_mutex == NULL) {
         uart_mutex = xSemaphoreCreateMutex();
     }
 
     while(1) {
         // Attend indéfiniment qu'un paquet soit disponible dans la file
         if(xQueueReceive(rx_queue, &packet, portMAX_DELAY)) {
             // Formatage du message de sortie avec:
             // - Numéro de séquence (tick count modulo 1000000)
             // - RSSI en dBm
             // - Taille de la trame en octets
             int pos = snprintf(output_buffer, sizeof(output_buffer),
                    "[%6lu|RSSI:%4ddB|%3dB] ",
                    xTaskGetTickCount() % 1000000,
                    packet->rssi,
                    packet->len - 1);
 
             // Ajout des octets de la trame en hexadécimal
             // Note: on commence à l'index 1 car l'index 0 contient la longueur
             for (int i = 1; i < packet->len; i++) {
                 pos += snprintf(output_buffer + pos, sizeof(output_buffer) - pos,
                                 "%02X", packet->data[i]);
             }
 
             // Ajout d'un retour à la ligne
             pos += snprintf(output_buffer + pos, sizeof(output_buffer) - pos, "\r\n");
 
             // Protection de l'accès à l'UART avec le mutex
             xSemaphoreTake(uart_mutex, portMAX_DELAY);
             uart_write_bytes(UART_PORT_NUM, output_buffer, pos);
             xSemaphoreGive(uart_mutex);
 
             // Libérer la mémoire du paquet traité
             free(packet);
         }
     }
 }
 
 /**
  * @brief Tâche FreeRTOS qui reçoit des données depuis l'UART
  * 
  * Cette tâche lit périodiquement l'UART pour:
  * 1. Traiter les commandes préfixées par CMD_PREFIX
  * 2. En mode TX, transmettre les données reçues en tant que trame IEEE 802.15.4
  * 
  * @param pvParameters Paramètres de la tâche (non utilisés)
  */
 static void uart_receive_task(void *pvParameters) {
     while (1) {
         // Lecture du port UART avec un timeout de 100ms
         int len = uart_read_bytes(UART_PORT_NUM, uart_data_buffer, BUF_SIZE-1, 100 / portTICK_PERIOD_MS);
         if (len > 0) {
             uart_data_buffer[len] = '\0';  // Ajouter un terminateur NULL pour faciliter le traitement de texte
             
             // Vérifier si c'est une commande (commence par CMD_PREFIX)
             if (strncmp((char*)uart_data_buffer, CMD_PREFIX, CMD_PREFIX_LEN) == 0) {
                 char* cmd = (char*)uart_data_buffer + CMD_PREFIX_LEN;  // Pointer après le préfixe
                 ESP_LOGI(TAG, "Commande reçue : %s", cmd);
                 
                 // Traiter les différentes commandes
                 if (strstr(cmd, "MODE_SNIFF")) switch_mode(MODE_SNIFF);  // Activer le mode capture
                 else if (strstr(cmd, "MODE_TX")) switch_mode(MODE_TX);   // Activer le mode transmission
                 else if (strstr(cmd, "STATUS")) {
                     // Commande d'affichage de l'état actuel du système
                     UBaseType_t queue_items = uxQueueMessagesWaiting(rx_queue);
                     ESP_LOGI(TAG, "État: Mode=%s, File=%d/%d, Paquets perdus=%lu", 
                             current_mode == MODE_SNIFF ? "SNIFF" : "TX", 
                             queue_items, QUEUE_SIZE, dropped_packets);
                 }
             } else if (current_mode == MODE_TX) {
                 // Si on est en mode TX et ce n'est pas une commande,
                 // considérer les données comme une trame à transmettre
                 uint8_t tx_frame[MAX_FRAME_SIZE + 1];
                 memcpy(tx_frame, uart_data_buffer, len);
                 // Transmettre la trame (false = ne pas attendre d'ACK)
                 esp_ieee802154_transmit(tx_frame, false);
             }
         }
     }
 }
 
 /**
  * @brief Fonction principale du firmware
  * 
  * Initialise tous les composants nécessaires:
  * - Stockage NVS
  * - Communication UART
  * - Radio IEEE 802.15.4
  * - File d'attente pour les paquets
  * - Tâches FreeRTOS pour la gestion des E/S
  */
 void app_main(void) {
     // Initialisation du stockage non-volatile
     initialize_nvs();
 
     // Configuration de l'UART
     uart_config_t uart_config = {
         .baud_rate = UART_BAUD_RATE,
         .data_bits = UART_DATA_8_BITS,
         .parity = UART_PARITY_DISABLE,
         .stop_bits = UART_STOP_BITS_1,
         .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
     };
     // Application de la configuration et installation du driver UART
     ESP_ERROR_CHECK(uart_param_config(UART_PORT_NUM, &uart_config));
     ESP_ERROR_CHECK(uart_driver_install(UART_PORT_NUM, BUF_SIZE, 0, 0, NULL, 0));
 
     // Activation de la radio IEEE 802.15.4 et configuration du canal
     ESP_ERROR_CHECK(esp_ieee802154_enable());
     ESP_ERROR_CHECK(esp_ieee802154_set_channel(CHANNEL));
     
     // Création de la file d'attente pour stocker les paquets reçus
     rx_queue = xQueueCreate(QUEUE_SIZE, sizeof(rx_packet_t *));
     
     // Démarrage en mode SNIFF par défaut
     switch_mode(MODE_SNIFF); 
 
     // Création des tâches FreeRTOS
     xTaskCreate(uart_receive_task, "uart_rx", 3072, NULL, 3, NULL); 
     xTaskCreate(uart_send_task, "uart_tx", 4096, NULL, 2, NULL);     
 
     // Affichage des informations de configuration
     ESP_LOGI(TAG, "Système initialisé");
     ESP_LOGI(TAG, "Configuration:");
     ESP_LOGI(TAG, "- Débit UART: %d bauds", UART_BAUD_RATE);
     ESP_LOGI(TAG, "- Canal radio: %d", CHANNEL);
     ESP_LOGI(TAG, "- Taille file: %d trames", QUEUE_SIZE);
 }