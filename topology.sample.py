
#  ----------------------- topology dict ------------------
"""
The Keys of the topology dictionary can only be switches

The values represent the connection to/from that switch. To create a link to another switch,
just write the switch#. To represent a connection to a host, write down a tuple containing the
host# and internal port address. An optional field for the host is the bridge name at tuple index 2.
The other two fields are mandatory

topology['switch number'] = [ ( 'host number' , 'internal port addr' , 'bridge_name'), 'switch' ]
"""  

#  ---------------------- switches dict, host dict ------------------   
"""
Keys: 
contr_addr = controller address for the switch (default none)
region = region name (defualt in config.y)
flavor = flavor name (default in config.py)
image = image name   (default in config.py)
bridge_name = bridge name for that switch
name = name of the VM associated with node (defaul: prefix+node_name)
vm_user_name = user used for ssh (default in config.py)
server = server on which the node is booted (default: None, up to system to pick)
- internal ip, when specified, it will add an internal ip with the name (tuple at index 0) 
  and address (tuple at index 1). Normally an internal ip is not allocated to a switch

NB: they can all be left blank
"""

contr_addr = '10.12.11.34:6633'

#Holds all switches
switches = {}
switches["sw1"] = {'contr_addr': contr_addr, 'region':'CORE', 'flavor': 'm1.small', 'bridge_name': 'sw1_br', 'int_ip':('p1', '192.168.200.18')}

#Holds all hosts
hosts = {}
hosts["h1"] = {'region':'CORE', 'flavor': 'm1.tiny'}
hosts["h2"] = {'region':'CORE', 'flavor': 'm1.tiny'}

topology = {}
topology["sw1"] = [('h1', '192.168.200.10', 'h1_br'), ('h2', '192.168.200.13')]

