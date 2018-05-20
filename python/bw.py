# -*- coding: utf-8 -*-
"""black widow stump module for IDE support

This document only exists to add IDE support for writing routers,
You can start any router with import'ing bw, and black-widow will overload it with it's own functions
"""


def publish_message(message_type, payload):
    """
    Publishes a message to all alive clients

    :param message_type: Message type, should be in between 0 and 127
    :param payload: The payload of the message
    :type message_type: int
    :type payload: bytes
    """
    pass


def send_message_to_client(message_type, payload, id):
    """
    Send a message to given client id, if it exists

    :param message_type: Message type, should be in between 0 and 127
    :param payload: The payload of the message
    :param id: the id of the client to send this message to
    :type message_type: int
    :type payload: bytes
    :type id: bytes
    """
    pass


def send_message_to_address(message_type, payload, addr, port):
    """
    Send a message to given address

    :param message_type: Message type, should be in between 0 and 127
    :param payload: The payload of the message
    :param addr: the ip of the client to send this message to
    :param port: the port of the client to send this message to
    :type message_type: int
    :type payload: bytes
    :type addr: str
    :type port: int
    """
    pass


def write_packet(packet):
    """
    Write the packet to this machine's tunnel

    :param packet: The packet to write to the current
    """

    pass


def add_packet_handler(handler):
    """
    Add a packet handler to the handler stack

    :param handler: The handler which should be called when a packet is received
    :type handler: Callable[[bytes], Any]
    :type pass_module: bool
    """

    pass


def add_message_handler(handler):
    """
    Add a message handler to the handler stack

    :param handler: The handler which should be called when a message is received
    :type handler: Callable[[int, bytes, str, int], Any]
    """
    pass


def log(message):
    """
    Since you stdio is unavailable while in black-widow, you can use this function to print stuff to stdout

    :param message: The message you want to print
    :type message: str
    """


__ALL__ = [
    publish_message,
    add_message_handler,
    add_packet_handler,
    send_message_to_address,
    send_message_to_client,
    write_packet
]
