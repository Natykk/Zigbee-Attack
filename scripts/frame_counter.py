"""
Module pour la gestion du frame counter et du numéro de séquence dans les trames Zigbee.
Ce module fournit des méthodes permettant d'incrémenter le frame counter et le numéro de séquence
dans une trame Zigbee, tout en garantissant que la longueur de la trame reste constante.
"""


class ZigbeeFrameFinder:
    def increment_frame_counter(self, trame_hex: str, increment: int = 10) -> str:
        """
        Incrémente le frame counter dans une trame Zigbee.

        Cette méthode extrait le frame counter (situé dans les 8 derniers caractères de la trame,
        plus précisément les 7e et 8e octets depuis la fin) et y ajoute une valeur d'incrément spécifiée.
        Le nouveau frame counter est alors converti en représentation hexadécimale (sur un octet en little-endian)
        et réintégré dans la trame à la même position, garantissant ainsi que la longueur de la trame reste inchangée.

        Args:
            trame_hex (str): La trame Zigbee au format hexadécimal.
            increment (int): La valeur à ajouter au frame counter (par défaut 10).

        Returns:
            str: La nouvelle trame avec le frame counter incrémenté.

        Raises:
            ValueError: Si la longueur de la trame change après l'incrémentation,
                        ce qui indiquerait une erreur dans le format de la trame.
        """
        current_fc = trame_hex[-8:-6]
        # Calcul du nouveau frame counter
        new_fc = int(current_fc, 16) + increment

        # Conversion en bytes (sur 1 octet, little-endian) puis en hex
        new_fc_hex = new_fc.to_bytes(1, byteorder='little').hex()

        # Reconstruction de la trame avec le nouveau frame counter
        new_trame = trame_hex[:-8] + new_fc_hex + trame_hex[-6:]
        if len(trame_hex) == len(new_trame):
            return new_trame
        else:
            raise ValueError("La longueur de la trame a changé après l'incrémentation du frame counter.")

    def increment_sequence_number(self, trame_hex: str, increment: int = 1) -> str:
        """
        Incrémente le numéro de séquence dans une trame Zigbee.

        Cette méthode extrait le numéro de séquence (les 4 derniers caractères de la trame,
        plus précisément les 3e et 4e octets depuis la fin), y ajoute la valeur d'incrément, 
        et reconstruit la trame en alternant la valeur du dernier octet selon une règle définie :
            - Si le dernier octet est '0'(off), il est remplacé par '01'(on).
            - Si le dernier octet est '1'(on), il est remplacé par '00'(off).
            - Sinon, '02'(toggle).

        Cette logique permet de gérer une alternance ou une alternance conditionnelle dans la trame.

        Args:
            trame_hex (str): La trame Zigbee au format hexadécimal.
            increment (int): La valeur à ajouter au numéro de séquence (par défaut 1).

        Returns:
            str: La nouvelle trame avec le numéro de séquence incrémenté.
        """
        current_sequence_number = trame_hex[-4:-2]
        # Incrémenter le numéro de séquence
        current_sequence_number = int(current_sequence_number, 16) + increment
        new_sequence_number = current_sequence_number.to_bytes(1, byteorder='little').hex()

        # Alternance basée sur la valeur du dernier octet
        if trame_hex[-1] == '0':
            return trame_hex[:-4] + new_sequence_number + '01'
        elif trame_hex[-1] == '1':
            return trame_hex[:-4] + new_sequence_number + '00'
        else:
            return trame_hex[:-4] + new_sequence_number + '02'
