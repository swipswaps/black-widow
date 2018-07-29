import bw
import os

# from random import randint

table = {}
table_own = {}
ip_known = {}

IP_PREFIX = [10, 61]
IP = IP_PREFIX + [0, 1]
INTERFACE = False
OWN_MAC = False
OWN_ID = False
COUNT = 2

MAC_TO_ID_TABLE = {}


def print_mac(mac: bytes):
    return str.join(':', [mac[i:i + 1].hex() for i in range(0, len(mac), 1)])


def print_ip(ip):
    return str.join('.', [str(part) for part in ip])


def handle_packet(packet):
    global MAC_TO_ID_TABLE

    dest = packet[0:6]
    source = packet[6:12]

    bw.log("tunnel: %s -> %s" % (print_mac(source), print_mac(dest)))

    MAC_TO_ID_TABLE[source] = OWN_ID

    if dest == b'\xff\xff\xff\xff\xff\xff':
        bw.publish_message(0, packet)
        return

    if dest not in MAC_TO_ID_TABLE:
        # Ignore unknown mac's
        print("└─> no client with mac(%s)" % print_mac(dest))
        return

    if MAC_TO_ID_TABLE[dest] == OWN_ID:
        print("└─> mac(%s) is owned by myself" % print_mac(dest))
        return

    bw.log("└─> conn(%s)" % MAC_TO_ID_TABLE[dest])
    bw.send_message_to_client(1, packet, MAC_TO_ID_TABLE[dest])


def handle_message(message_type, payload, ip, port, client_id):
    global MAC_TO_ID_TABLE

    if message_type in [0, 1]:
        source = payload[6:12]
        dest = payload[0:6]

        bw.log("conn(%s): %s -> %s" % (client_id, print_mac(source), print_mac(dest)))

        MAC_TO_ID_TABLE[source] = client_id

        bw.write_packet(payload)

    bw.log("conn(%s): got unknown message type: %s" % (client_id, message_type))


def on_boot(interface, own_id):
    global INTERFACE, OWN_MAC, OWN_ID

    INTERFACE = interface
    OWN_MAC = os.popen('ip l show %s | grep -o "ether [A-Fa-f0-9:]\+"' % INTERFACE).read().strip()[6:]
    OWN_ID = own_id

    os.system('ip l set %s up' % INTERFACE)
    os.system('ip a flush dev %s' % INTERFACE)
    os.system('ip a add %s dev %s' % (print_ip(IP), INTERFACE))
    os.system('ip r add 10.61.0.0/16 dev %s' % INTERFACE)

    bw.log("Interface: %s, Mac: %s, Ip: %s" % (INTERFACE, OWN_MAC, print_ip(IP)))


bw.add_packet_handler(handle_packet)
bw.add_message_handler(handle_message)
bw.add_boot_handler(on_boot)

bw.log("Started example router.")
