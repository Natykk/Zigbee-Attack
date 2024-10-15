/*
 * SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file main.c
 * @brief Application console Zigbee pour ESP32
 */

#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_zigbee_all_device_types_app.h"

static const char *TAG = "ESP_ZB_CONSOLE_APP";

/**
 * @brief Journaliser les informations du réseau Zigbee
 *
 * Cette fonction récupère et journalise l'ID PAN étendu, l'ID PAN,
 * le canal et l'adresse courte du réseau Zigbee actuel.
 *
 * @param status_string Message d'état à journaliser
 */
static void log_nwk_info(const char *status_string)
{
    esp_zb_ieee_addr_t extended_pan_id;
    esp_zb_get_extended_pan_id(extended_pan_id);
    ESP_LOGI(TAG, "%s (Extended PAN ID: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, PAN ID: 0x%04hx, "
                  "Canal:%d, Adresse courte: 0x%04hx)", status_string,
                  extended_pan_id[7], extended_pan_id[6], extended_pan_id[5], extended_pan_id[4],
                  extended_pan_id[3], extended_pan_id[2], extended_pan_id[1], extended_pan_id[0],
                  esp_zb_get_pan_id(), esp_zb_get_current_channel(), esp_zb_get_short_address());
}

/**
 * @brief Gestionnaire de signal de la pile Zigbee
 *
 * Gère divers signaux Zigbee tels que les annonces de périphériques, la formation de réseau,
 * et la gestion du réseau. Journalise l'état du réseau ou les erreurs en fonction du type de signal.
 *
 * @param signal_struct Structure contenant les données de signal Zigbee
 */
void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal_struct)
{
    uint32_t *p_sg_p     = signal_struct->p_app_signal;
    esp_err_t err_status = signal_struct->esp_err_status;
    esp_zb_app_signal_type_t sig_type = *p_sg_p;
    esp_zb_zdo_signal_device_annce_params_t *dev_annce_params = NULL;
    esp_zb_zdo_signal_leave_indication_params_t *leave_ind_params = NULL;
    const char *err_name = esp_err_to_name(err_status);
    switch (sig_type) {
    case ESP_ZB_ZDO_SIGNAL_SKIP_STARTUP:
        ESP_LOGI(TAG, "Initialisation de la pile Zigbee");
        break;
    case ESP_ZB_BDB_SIGNAL_DEVICE_FIRST_START:
    case ESP_ZB_BDB_SIGNAL_DEVICE_REBOOT:
        if (err_status == ESP_OK) {
            ESP_LOGI(TAG, "L'appareil a démarré en mode %s réinitialisé", esp_zb_bdb_is_factory_new() ? "" : "non");
        } else {
            ESP_LOGE(TAG, "Échec de l'initialisation de la pile Zigbee (statut : %s)", err_name);
        }
        break;
    case ESP_ZB_BDB_SIGNAL_FORMATION:
        if (err_status == ESP_OK) {
            log_nwk_info("Réseau formé avec succès");
        } else {
            ESP_LOGI(TAG, "Échec de la formation du réseau (statut : %s)", err_name);
        }
        break;
    case ESP_ZB_BDB_SIGNAL_STEERING:
        if (err_status == ESP_OK) {
            log_nwk_info("Réseau rejoint avec succès");
        } else {
            ESP_LOGI(TAG, "Échec de la jonction au réseau (statut : %s)", err_name);
        }
        break;
    case ESP_ZB_ZDO_SIGNAL_LEAVE:
        if (err_status == ESP_OK) {
            ESP_LOGI(TAG, "Appareil quitté le réseau avec succès");
        } else {
            ESP_LOGE(TAG, "Échec du départ du réseau (statut : %s)", err_name);
        }
        break;
    case ESP_ZB_ZDO_SIGNAL_LEAVE_INDICATION:
        leave_ind_params = (esp_zb_zdo_signal_leave_indication_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        ESP_LOGI(TAG, "Nœud Zigbee (0x%04hx) quitte le réseau", leave_ind_params->short_addr);
        break;
    case ESP_ZB_ZDO_SIGNAL_DEVICE_ANNCE:
        dev_annce_params = (esp_zb_zdo_signal_device_annce_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        ESP_LOGI(TAG, "Nouveau périphérique commissionné ou rejoint (court : 0x%04hx)", dev_annce_params->device_short_addr);
        break;
    case ESP_ZB_NWK_SIGNAL_PERMIT_JOIN_STATUS:
        if (err_status == ESP_OK) {
            if (*(uint8_t *)esp_zb_app_signal_get_params(p_sg_p)) {
                ESP_LOGI(TAG, "Réseau (0x%04hx) ouvert pour %d secondes", esp_zb_get_pan_id(), *(uint8_t *)esp_zb_app_signal_get_params(p_sg_p));
            } else {
                ESP_LOGW(TAG, "Réseau (0x%04hx) fermé, jonction de périphériques non autorisée.", esp_zb_get_pan_id());
            }
        }
        break;
    case ESP_ZB_BDB_SIGNAL_TOUCHLINK_TARGET:
        ESP_LOGI(TAG, "Cible Touchlink prête, en attente de commissionnement");
        break;
    case ESP_ZB_BDB_SIGNAL_TOUCHLINK_NWK:
        if (err_status == ESP_OK) {
            log_nwk_info("Commissionnement Touchlink réussi");
        } else {
            ESP_LOGW(TAG, "Échec du commissionnement Touchlink (statut : %s)", err_name);
        }
        break;
    case ESP_ZB_BDB_SIGNAL_TOUCHLINK_TARGET_FINISHED:
        ESP_LOGI(TAG, "Cible Touchlink terminée (statut : %s)", err_name);
        break;
    case ESP_ZB_BDB_SIGNAL_TOUCHLINK_NWK_STARTED:
    case ESP_ZB_BDB_SIGNAL_TOUCHLINK_NWK_JOINED_ROUTER:
        ESP_LOGI(TAG, "L'initiateur Touchlink reçoit la réponse pour le réseau %s",
                 sig_type == ESP_ZB_BDB_SIGNAL_TOUCHLINK_NWK_STARTED ? "démarré" : "rejoindre routeur");
        esp_zb_bdb_signal_touchlink_nwk_params_t *sig_params = (esp_zb_bdb_signal_touchlink_nwk_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        ESP_LOGI(TAG, "Réponse du profil : 0x%04hx, point de terminaison : %d, adresse : 0x%16" PRIx64,
                      sig_params->profile_id, sig_params->endpoint, *(uint64_t*)sig_params->device_ieee_addr);
        break;
    case ESP_ZB_BDB_SIGNAL_TOUCHLINK:
        if (err_status == ESP_OK) {
            log_nwk_info("Commissionnement Touchlink réussi");
        } else {
            ESP_LOGW(TAG, "Aucun périphérique cible Touchlink trouvé");
        }
        break;
    default:
        ESP_LOGI(TAG, "Signal ZDO : %s (0x%x), statut : %s", esp_zb_zdo_signal_to_string(sig_type), sig_type,
                 err_name);
        break;
    }
}

/**
 * @brief Initialiser la pile Zigbee
 *
 * Cette fonction initialise la pile Zigbee avec des configurations par défaut et
 * définit les canaux réseau autorisés par défaut pour l'analyse.
 */
void zb_stack_init(void)
{
    /* Initialiser la pile Zigbee avec la configuration par défaut */
    esp_zb_cfg_t zb_nwk_cfg = ESP_ZB_ZR_CONFIG();
    esp_zb_init(&zb_nwk_cfg);

    /* Définir les canaux réseau autorisés par défaut */
    esp_zb_set_channel_mask(ESP_ZB_TRANSCEIVER_ALL_CHANNELS_MASK);

    /* Définir les canaux d'analyse par défaut */
    esp_zb_set_primary_network_channel_set(ESP_ZB_TRANSCEIVER_ALL_CHANNELS_MASK);
    esp_zb_set_secondary_network_channel_set(ESP_ZB_TRANSCEIVER_ALL_CHANNELS_MASK);

    /* Activer la gestion CLI de ep_list */
    esp_zb_console_manage_ep_list(NULL);
}

/**
 * @brief Tâche principale Zigbee
 *
 * Cette fonction est la tâche principale responsable de l'exécution de la pile Zigbee. La pile
 * est initialisée mais non démarrée, permettant une configuration via le CLI avant de démarrer.
 *
 * @param pvParameters Paramètres passés à la tâche (non utilisés)
 */
static void zb_stack_main_task(void *pvParameters)
{
    zb_stack_init();

    /* Ne pas appeler `esp_zb_start()`.
     *
     * Nous voulons que le démarrage de la pile soit géré par le CLI,
     * pour avoir la possibilité de configurer la pile.
     */

    esp_zb_stack_main_loop();

    esp_zb_console_deinit();
    vTaskDelete(NULL);
}

/**
 * @brief Point d'entrée de l'application
 *
 * Il s'agit du point d'entrée principal de l'application. Il initialise
 * le stockage non volatil (NVS), la console Zigbee et la plateforme, puis
 * démarre la tâcheVoici la fin de la tâche principale Zigbee et le point d'entrée de l'application avec les commentaires en français :

```c
    esp_zb_stack_main_loop();

    esp_zb_console_deinit();
    vTaskDelete(NULL);
}

/**
 * @brief Point d'entrée de l'application
 *
 * Il s'agit du point d'entrée principal de l'application. Il initialise
 * le stockage non volatile (NVS), la console Zigbee et la plateforme, puis
 * démarre la tâche principale Zigbee.
 */
void app_main(void)
{
    esp_zb_platform_config_t config = {
        .radio_config = ESP_ZB_DEFAULT_RADIO_CONFIG(),
        .host_config = ESP_ZB_DEFAULT_HOST_CONFIG(),
    };
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_zb_console_init());
    ESP_ERROR_CHECK(esp_zb_platform_config(&config));
    xTaskCreate(zb_stack_main_task, "Zigbee_main", 4096, NULL, 5, NULL);
    ESP_LOGI(TAG, "Démarrer la console ESP Zigbee");
    ESP_ERROR_CHECK(esp_zb_console_start());
}
