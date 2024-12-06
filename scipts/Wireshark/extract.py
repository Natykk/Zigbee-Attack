import pyshark


def analyze_zigbee_with_decryption(file_path, zigbee_network_key="5A6947426565416C6C69616E63653039"):
    """
    Analyse un fichier pcapng Zigbee et affiche les informations des paquets, avec déchiffrement simulé.

    :param file_path: Chemin vers le fichier pcapng.
    :param zigbee_network_key: Clé réseau Zigbee (hexadécimale) pour déchiffrer les données.
    """
    try:
        # Charger le fichier avec un filtre Zigbee
        capture = pyshark.FileCapture(file_path)
    except Exception as e:
        print(f"Erreur lors du chargement du fichier : {e}")
        return

    print(f"\nAnalyse des paquets Zigbee dans : {file_path}")
    print("=" * 70)
    print(f"Clé réseau utilisée pour le déchiffrement : {zigbee_network_key}\n")

    for packet in capture:
        try:
            
        
            print("\n--- Nouveau Paquet Zigbee ---")
            for layer in packet.layers:
                print(f"Layer : {layer.layer_name}")
                #cprint(dir(layer))
                if (layer.layer_name == "zbee_nwk"):
                    print(f"Source : {layer.src}")
                    print(f"Destination : {layer.dst}")
                    print(f"données {layer.data}")

                if(layer.layer_name == "wpan"):
                    print("wpan !!!!")
                    
                if(layer.layer_name == "zbee_zcl"):
                    print(f"Cluster ID : {layer.cluster_id}")
                    print(f"Command ID : {layer.cmd_id}")
                    print(f"Payload : {layer.zcl_payload}")
                



            '''
            print(f"Protocole : {packet.layers.layer_name}")
            print(f"Numéro du paquet : {packet.number}")
            print(f"Temps de capture : {packet.sniff_time}")

            # Adresses source et destination (NWK Layer)
            if hasattr(packet, "zbee_nwk"):
                src_addr = packet.zigbee_nwk.src
                dst_addr = packet.zigbee_nwk.dst
                print(f"Adresse NWK Source : {src_addr}")
                print(f"Adresse NWK Destination : {dst_addr}")
            else:
                print("Informations NWK non disponibles.")

            # Informations sur ZCL (Cluster Library)
            if hasattr(packet, "zbee_zcl"):
                cluster_id = packet.zigbee_zcl.cluster_id
                command_id = packet.zigbee_zcl.cmd_id
                payload = getattr(packet.zigbee_zcl, 'zcl_payload', "Non disponible")
                print(f"Cluster ID : {cluster_id}")
                print(f"Command ID : {command_id}")
                print(f"Payload : {payload}")
            else:
                print("Paquet ZCL non trouvé.")

            # Gestion des paquets
            if hasattr(packet, "zbee_app_payload"):
                # Données chiffrées
                encrypted_data = packet.zbee_app_payload
                print(f"Données chiffrées : {encrypted_data}")

                # Déchiffrement simulé
                decrypted_data = bytes.fromhex(encrypted_data) ^ bytes.fromhex(zigbee_network_key)
                print(f"Données déchiffrées : {decrypted_data.hex()}")
            else:
                print("Données applicatives non trouvées.")

            '''


        except Exception as e:
            print(f"Erreur lors de l'analyse du paquet : {e}")


    capture.close()
    print("\nAnalyse terminée.")



# Exemple d'utilisation
if __name__ == "__main__":
    # Chemin du fichier .pcapng Zigbee
    file_path = "light_switch.pcapng"

    # Clé réseau Zigbee par défaut (ZigbeeAlliance09)
    zigbee_network_key = "5A6947426565416C6C69616E63653039"

    analyze_zigbee_with_decryption(file_path, zigbee_network_key)
