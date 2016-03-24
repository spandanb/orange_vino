"""
Provides some utility functions
"""
from prettytable import PrettyTable
import re

def pretty_print(table):
    """
    pretty print table
    Arguments:
        table is a list of lists(rows)
    """
    header, body = table[0], table[1:]
    ptable = PrettyTable(header)
    for row in body:
        ptable.add_row(row)

    print ptable

def format_and_print(info_map):
    """
    format the info about a server
    """
    table = [("Property", "Value")] + info_map.items()
    pretty_print(table)

def overlay_ip(ip_addr):
    """
    Returns an overlay IP addr for
    an underlay IP

    x.x.a.b -> 192.168.a.b
    """
    suffix = ".".join(ip_addr.split(".")[2:4])
    return "192.168." + suffix

def is_prefix(prefix, string):
    """
    if prefix is a prefix in the string
    """
    return string.find(prefix) == 0

def is_uuid(string):
    """
    Returns true if input 
    string is a UUID
    The UUID must only have lowercase alphabets
    and dashes as per the human-readable canonical form
    """
    return not not re.match(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', string)

def extract_ip(host_port):
    """
    Takes <IP>:<port> and returns
    <IP>
    """
    return host_port.split(":")[0]
