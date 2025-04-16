# README - Projet Zigbee

## 📖 Description du Projet
Le projet Zigbee consiste à implémenter un banc d’attaque sur des appareils utilisant le protocole Zigbee. Zigbee est un protocole de communication largement utilisé dans les réseaux IoT (Internet of Things), en particulier pour les environnements domestiques et industriels. Cependant, en raison de certaines vulnérabilités intrinsèques, Zigbee peut être une cible pour différentes attaques.

Dans ce projet, nous explorerons les mécanismes de sécurité du protocole Zigbee et reproduirons plusieurs scénarios d’attaques. Ces travaux permettront d’identifier les failles et d’améliorer la compréhension des menaces potentielles, tout en documentant les résultats et les solutions possibles.

### Objectifs :
1. Étudier les mécanismes de sécurité du protocole Zigbee et ses vulnérabilités.
2. Configurer un banc de test matériel et logiciel pour exécuter des scénarios d’attaques.
3. Reproduire des attaques simples (comme le brouillage) et complexes (comme l’usurpation d’identité).
4. Documenter les travaux et proposer des recommandations pour améliorer la sécurité.

### Matériel et Frameworks Utilisés :
- **Matériel** :
  - 2x ESP32-H2 (1x [HA_on_off_light](https://github.com/espressif/esp-idf/tree/master/examples/zigbee/light_sample/HA_on_off_light) , 1x [HA_on_off_switch](https://github.com/espressif/esp-idf/tree/master/examples/zigbee/light_sample/HA_on_off_switch) )
  - 1x ESP32-H2 utilisant [https://forgens.univ-ubs.fr/gitlab/e2003623/projet-zigbee/-/blob/main/code/firmware/esp_sniff_envoie.c?ref_type=heads](esp_sniff_envoie.c)

## 🛠️ Liste des Tâches

### Étape 1 : Étude des attaques et du protocole Zigbee
- [x] **1.1 Recherche Littérature Attaque Zigbee**
  - [x] Recherche attaque brouillage et interception 
  - [x] Recherche attaque usurpation d'identité et rejeu 
- [x] **1.2 Étude de la sécurité du Protocole Zigbee**
  - [x] Étude des mécanismes d'authentification et gestion des clés 
  - [x] Recherche des mécanismes de chiffrement et leurs vulnérabilités 

### Étape 2 : Préparation Banc de Test Zigbee
- [x] **2.1 Configuration Matériel et Logiciel** 
- [x] **2.2 Mise en place d'outils**
  - [x] Test d'attaques par brouillage et interception 
  - [x] Test d'attaques par rejeu 

### Étape 3 : Reproduction des Scénarios d'attaques Zigbee
- [x] **3.1 Reproduction d'attaques simples**
  - [x] Attaque de brouillage 
  - [x] Attaque d'interception 
- [x] **3.2 Reproduction d'attaques complexes**
  - [x] Attaque par rejeu 

### Étape 4 : Documentation et Code
- [x] **4.1 Documentation du Banc de Test et des Attaques**
  - [x] Attaques par brouillage et interception 
  - [x] Attaques par rejeu 
- [x] **4.2 Finalisation du Code et Documentation** 


## 📂 Structure du Dépôt
- `/docs` : Tous les rapports et guides.
- `/scripts` : Scripts et configurations pour le banc de test.
- `/report` : Résultats et logs des scénarios d'attaques.

## 📖 Références
Pour plus d’informations sur le protocole Zigbee et les attaques étudiées, consultez la documentation associée dans `/docs`.

## Exemples
Des exemples d'utilisation des différentes modules sont disponible dans le init.py 

