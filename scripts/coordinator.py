"""
Ce module implémente un coordinateur Zigbee avec WHAD.

Classes
-------
CodeurTrameZigbee : Classe pour encoder des trames Zigbee. 
"""

import whad.zigbee.connector.coordinator
from whad.device import WhadDevice
from whad.dot15d4 import Dot15d4
from scapy.layers.dot15d4 import Dot15d4FCS

def create_device_instance():
    """
    Crée une instance de périphérique compatible en utilisant l'interface série spécifiée.
    
    Parameters
    ----------
    None

    Returns
    -------
    WhadDevice
        Une instance de `WhadDevice` pour l'interface série "uart2".

    Raises
    ------
    Exception
        Si l'instance ne peut pas être créée.
    """
    try:
        # Création de l'instance de périphérique sur "uart2"
        device = WhadDevice.create("uart2")
        return device
    except Exception as e:
        raise Exception("Erreur lors de la création du périphérique: " + str(e))


def start_zigbee_network(device):
    """
    Démarre un réseau Zigbee en tant que coordinateur avec les paramètres spécifiés.
    
    Parameters
    ----------
    device : WhadDevice
        L'instance de périphérique utilisée pour la connexion au réseau.

    Returns
    -------
    str
        Le résultat de la méthode `start_network` indiquant le succès ou l'échec de l'initialisation.

    Raises
    ------
    Exception
        Si le réseau ne peut pas être démarré.
    """
    try:
        # Création d'un coordinateur Zigbee
        nwk = whad.zigbee.connector.coordinator.Coordinator(device)
        
        # Démarrage du réseau Zigbee
        ret = nwk.start_network(13, 1122334455667788990, None)
        
        # Activation de la réception des messages
        nwk.enable_reception()
        
        return ret
    except Exception as e:
        raise Exception("Erreur lors du démarrage du réseau Zigbee: " + str(e))


def main():
    """
    Fonction principale qui gère la création du périphérique et du réseau Zigbee.
    
    - Crée une instance du périphérique compatible.
    - Démarre un réseau Zigbee et active la réception des données.
    - Affiche le résultat du démarrage du réseau Zigbee.
    
    Si une erreur survient à n'importe quelle étape, un message d'erreur est affiché.
    
    Parameters
    ----------
    None

    Returns
    -------
    None
    """
    try:
        # Création du périphérique compatible
        device = create_device_instance()
        
        # Démarrage du réseau Zigbee et réception des résultats
        result = start_zigbee_network(device)
        
        # Affichage du résultat du démarrage
        print(result)
    except Exception as e:
        print("Erreur: " + str(e))

if __name__ == "__main__":
    main()
