import bw
import os
from random import randint

table = {}
table_own = {}
ip_known = {}

IP_PREFIX = [10, 21]
IP = IP_PREFIX + [randint(0, 255), randint(1, 255)]
INTERFACE = False
OWN_MAC = False
COUNT = 2


def print_mac(mac: bytes):
    return str.join(':', [mac[i:i + 1].hex() for i in range(0, len(mac), 1)])


def print_ip(ip):
    return str.join('.', [str(part) for part in ip])


def handle_packet(packet, _):
    bw.publish_message(0, packet)


def handle_message(message_type, payload, ip, port, client_id, _):
    if message_type == 0:
        bw.write_packet(payload)


def on_boot(interface, _):
    global INTERFACE, OWN_MAC

    INTERFACE = interface
    OWN_MAC = os.popen('ip l show %s | grep -o "ether [A-Fa-f0-9:]\+"' % INTERFACE).read().strip()[6:]

    os.system('ip l set %s up' % INTERFACE)
    os.system('ip a flush dev %s' % INTERFACE)
    os.system('ip a add %s dev %s' % (print_ip(IP), INTERFACE))
    os.system('ip r add 10.21.0.0/16 dev %s' % INTERFACE)
    # os.system('brctl addif test-bw %s' % INTERFACE)

    bw.log("Interface: %s, Mac: %s, Ip: %s" % (INTERFACE, OWN_MAC, print_ip(IP)))


bw.add_packet_handler(handle_packet)
bw.add_message_handler(handle_message)

bw.add_boot_handler(on_boot)

bw.log("Started example router.")
