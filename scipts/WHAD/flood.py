from whad.device import WhadDevice
from whad.dot15d4 import Dot15d4
from scapy.layers.dot15d4 import Dot15d4FCS
#from whad.core import logger
# Create a compatible device instance
device = WhadDevice.create("uart0")

# Use a default Dot15d4 connector
connector = Dot15d4(device)


# Construire un paquet 802.15.4 avec Scapy
packet = Dot15d4FCS(fcs=0) / b"Hello World!"
while(1):
    # Send 802.15.4 packet
    ret = connector.send(packet,channel=13)
    print(ret)