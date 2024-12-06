import whad.zigbee.connector.coordinator
from whad.device import WhadDevice
from whad.dot15d4 import Dot15d4
from scapy.layers.dot15d4 import Dot15d4FCS

# Create a compatible device instance
device = WhadDevice.create("uart0")


nwk = whad.zigbee.connector.coordinator.Coordinator(device)

#Fais un reseau Zigbee sur le canal 11 avec le extended PAN ID 1122334455667788990 et la clé de chiffrement None
ret =nwk.start_network(13,1122334455667788990,None)

print(ret)




