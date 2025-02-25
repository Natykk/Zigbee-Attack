"""
Module pour la gestion du frame counter et du numero de séquence dans les trames Zigbee.
"""
class ZigbeeFrameFinder:

    def increment_frame_counter(self, trame_hex: str, increment: int = 10) -> str:
        """
        Incrémente le frame counter dans la trame.
        
        Args:
            trame_hex (str): Trame Zigbee en format hexadécimal
            increment (int): Valeur d'incrémentation
            
        Returns:
            str: Nouvelle trame avec frame counter incrémenté
        """
        current_fc = trame_hex[-8:-6] 
        
            
        # Calcul du nouveau frame counter
        new_fc = int(current_fc,16) + increment
        
        # Conversion en bytes little-endian puis en hex
        new_fc_hex = new_fc.to_bytes(1, byteorder='little').hex()
        
        # Reconstruction de la trame
        return trame_hex[:-8] + new_fc_hex + trame_hex[-6:]
    def increment_sequence_number(self, trame_hex: str, increment: int = 1) -> str:
        """
        Incrémente le frame counter dans la trame.
        
        Args:
            trame_hex (str): Trame Zigbee en format hexadécimal
            increment (int): Valeur d'incrémentation
            
        Returns:
            str: Nouvelle trame avec numero de séquence incrémenté
        """

        current_sequence_number = trame_hex[-4:-2]
        current_sequence_number = int(current_sequence_number,16)+increment
        new_sequence_number = current_sequence_number.to_bytes(1, byteorder='little').hex()
        return trame_hex[:-4] + new_sequence_number + '02'


