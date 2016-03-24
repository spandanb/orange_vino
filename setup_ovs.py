from jinja2 import Template
import sys
from orc import Orc
import config
import utils as ut
import ansible_wrapper
import pdb 
"""
The 
get topology file and ip addr of each host
for host in hosts:
    instantiate template, i.e. create_ovs_script(host)
    run ansible, i.e. command mode
"""

def setup_host(bridge='br0', int_port='p0', int_ip=None, ip='', 
        contr_addr=None, connections=None):
    """
    Setup ovs for each individual host

    Parameters:
        bridge: bridge name
        int_port: internal port name
        int_ip: overlay ip for this node
        ip: IP Addr of current host
        contr_addr: controller address
            ["X.X.X.X" | None] if, None switches setup in
            stanalone mode
        connections: the nodes that have vxlan connection
            with this node [{'remote_ip': ####, 'vni': #}] 
        standalone: whether the switches are standalone or 
            need controller
    """
    print "Setting up ovs for {}".format(ip)
    #read the template file
    if contr_addr is None:
        template_name = 'config_ovs_standalone.template.sh'
    else:
        template_name = 'config_ovs.template.sh'
    with open(template_name) as template_file:
        template = Template(template_file.read())

    #instantiate the template
    #create ovs-setup script for this host
    script_text = template.render(bridge=bridge, contr_addr=contr_addr, 
        int_port=int_port, int_ip=int_ip, connections=connections)
    
    #write the script to an actual file
    script_name = "config_ovs.sh"
    with open(script_name, "w") as script:
       script.write(script_text) 

    #call ansible
    results = ansible_wrapper.playbook('ovs_config_play.yaml', [ip])
    #print results
    ansible_wrapper.print_results(results)

def setup_ovs_swarm(topology=None, nodes=None, contr_addr="10.12.1.20:6633"):
    """
    Setup ovs over each host in the topology
    Parameters:
        topology: dict of interconections 
        nodes: list/dict of nodes and their properties
            e.g. IP address
        contr_addr: ["X.X.X.X"|None] if None, configures switches
            in stanalone mode
    """
    if not topology:
        #NOTE: This may potentially cause a circular dependency
        orc = Orc()
        topology = orc.topology

    if not nodes:
        if not orc: 
            orc = Orc()
        nodes = orc.get_topology()

    if type(nodes) == list:
        #transform nodes into nodename mapped dict
        node_dict = {}
        for node in nodes:
            ut.is_prefix(config.instance_prefix, node['name'])
            node_name = node['name'][len(config.instance_prefix): ]
            node_dict[node_name] = node
        nodes = node_dict

    def _get_connections(remote):
        """remote_node obj -> {'vni':#, 'remote_ip': remote_node IP}"""
        #NOTE: all nodes share the VNI
        return {'vni':1, 'remote_ip': nodes[remote]['addr']}

    for node_name, node in nodes.items():
        connections = map(_get_connections, topology[node_name])
        setup_host(contr_addr=contr_addr,
                   connections=connections,
                   int_ip = ut.overlay_ip(node['addr']),
                   ip = node['addr'])


def setup_ovs_from_hosts(hosts=[], contr_addr="10.12.1.20"):
    """
    Similar to setup_ovs_swarm, except takes a list of hosts
    Arguments:
        hosts:- is a list of IP addresses
        contr_addr: ["X.X.X.X"|None] if None, configures switches
            in stanalone mode
    """
    for idx in range(len(hosts)):
        host = hosts[idx]
        connections = hosts[:idx] + hosts[idx+1:]
        connections = map(lambda conn: {'remote_ip': conn, 'vni': 1}, connections)
        setup_host(contr_addr=contr_addr,
                   connections=connections,
                   int_ip = ut.overlay_ip(host),
                   ip = host)


if __name__ == "__main__":
    #setup_ovs_swarm()
    setup_ovs_from_hosts(hosts=["10.12.0.20", "10.12.0.21"], contr_addr="10.12.1.20:6633")
