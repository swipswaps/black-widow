import bw
from scapy.layers.l2 import *
from scapy.layers.dhcp import *
from scapy.layers.dhcp6 import *

table = {}

table_own = {}


def print_mac(mac: bytes):
    return str.join(':', [mac[i:i + 1].hex() for i in range(0, len(mac), 1)])

def handle_packet(packet, _):
    ether = Ether(packet)

    if ether.haslayer(DHCP):
        handle_dhcp(packet)

def handle_dhcp(packet: Ether):
    if packet.haslayer(DHCP):
        return

    dhcp = packet[DHCP]

    for option in dhcp.options:
        if option[0] == 'message-type':
            op = option[1]

            # discover
            if op == 1:
                pass



def handle_message(message_type, payload, ip, port, client_id, _):
    pass


bw.add_packet_handler(handle_packet)
bw.add_message_handler(handle_message)

bw.log("Started example router.")
