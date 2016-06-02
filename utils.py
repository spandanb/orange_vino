"""
Provides some utility functions
"""
from prettytable import PrettyTable
import re
import time

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

class SleepFSM(object):
    """
    Makes current process sleep starting with
    time =  `sleep_time` and doubles every time
    sleep is called until `max_tries`, whence
    a Error is raised
    """

    def init(self, max_tries=5, sleep_time=20):
        """(re)starts the FSM
        """
        self.max_tries = max_tries
        self.sleep_time = sleep_time
        self.current_try = 0

    def sleep(self):
        if self.current_try == self.max_tries:
            raise RuntimeError('Maximum tries exceeded')

        time.sleep(self.sleep_time)
        #Increment try counter
        self.current_try += 1
        #Double sleep time
        self.sleep_time = self.sleep_time * 2

    def __call__(self):
        self.sleep()

def create_and_raise(exception_name, exception_msg):
    """
    Creates a new Exception sub class and raises it.
    Arguments:
        exception_name:- name of exception class
        exception_msg: msg associated with exception
    """
    #Create exception
    ExceptionClass = type(exception_name, (Exception, ), {})
    #define __init__ method
    def exception__init__(self, message):
        super(ExceptionClass, self).__init__(message)
    ExceptionClass.__init__ = exception__init__

    #Now raise the exception
    raise ExceptionClass(exception_msg)
