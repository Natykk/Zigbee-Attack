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
  - Dongle USB TI CC2531
  - CC Debugger
  - Raspbee II
  - ESP32-H2
- **Frameworks** :
  - Killerbee
  - ZigDiggity

## 🛠️ Liste des Tâches

### Étape 1 : Étude des attaques et du protocole Zigbee
- [x] **1.1 Recherche Littérature Attaque Zigbee**
  - [x] Recherche attaque brouillage et interception (Théo)
  - [x] Recherche attaque usurpation d'identité et rejeu (Nathan)
- [x] **1.2 Étude de la sécurité du Protocole Zigbee**
  - [x] Étude des mécanismes d'authentification et gestion des clés (Théo)
  - [x] Recherche des mécanismes de chiffrement et leurs vulnérabilités (Nathan)

### Étape 2 : Préparation Banc de Test Zigbee
- [x] **2.1 Configuration Matériel et Logiciel** (Théo & Nathan)
- [ ] **2.2 Mise en place d'outils**
  - [ ] Test d'attaques par brouillage et interception (Théo)
  - [ ] Test d'attaques par rejeu et usurpation (Nathan)

### Étape 3 : Reproduction des Scénarios d'attaques Zigbee
- [ ] **3.1 Reproduction d'attaques simples**
  - [ ] Attaque de brouillage (Théo)
  - [ ] Attaque d'interception (Nathan)
- [ ] **3.2 Reproduction d'attaques complexes**
  - [ ] Attaque par rejeu (Théo)
  - [ ] Attaque par usurpation d'identité (Nathan)

### Étape 4 : Documentation et Code
- [ ] **4.1 Documentation du Banc de Test et des Attaques**
  - [ ] Attaques par brouillage et interception (Théo)
  - [ ] Attaques par rejeu et usurpation (Nathan)
- [ ] **4.2 Finalisation du Code et Documentation** (Théo & Nathan)



## 🤝 Contributeurs
- **Gauteron Nathan**
- **Peletier Théo**

## 📂 Structure du Dépôt
- `/docs` : Tous les rapports et guides.
- `/scripts` : Scripts et configurations pour le banc de test.
- `/report` : Résultats et logs des scénarios d'attaques.

## 📖 Références
Pour plus d’informations sur le protocole Zigbee et les attaques étudiées, consultez la documentation associée dans `/docs`.

---

Vous pouvez utiliser les cases à cocher pour suivre l'avancement directement dans GitHub.
