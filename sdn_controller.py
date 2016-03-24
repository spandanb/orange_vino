"""
This should be used when overlay topology is 
created in mesh mode.
This is used to "enforce" the topology through
the controller
"""
import cPickle as pickle
import os
from orc import Orc
import config
import utils as ut

def get_rules(topology, nodes, overlay=True):
    """
    Returns {'ip_addr' -> [Acceptable IPs]}

    This takes `nodes` in the post-process form
    i.e. use if sdn_controller is being called 
    as a standalone script

    Arguments:-
        overlay- translate IPs to overlay IPs 
    """
    #First create a node name -> node IP addr
    name_ip_map = {}
    for node in nodes:
        unqualified_name = node["name"][len(config.instance_prefix):]
        name_ip_map[unqualified_name] = node["addr"]
    
    #Rules is an IP connectivity graph
    rules = {}
    for node, connections in topology.items():
        src = name_ip_map[node]
        whitelist = [name_ip_map[conn] for conn in connections]
        if overlay:
            src = ut.overlay_ip(src)
            whitelist = map(ut.overlay_ip, whitelist)
        rules[src] = whitelist 

    return rules

def get_rules_from_topology(topology, nodes, overlay=True):
    """
    This takes `nodes` in the stream form, i.e.
    use if topology and nodes are as when orc is 
    creating topology
    """
    rules = {}
    for node, connections in topology.items():
        src = nodes[node]['addr']
        whitelist = [nodes[conn]['addr'] for conn in connections]
        if overlay:
            src = ut.overlay_ip(src)
            whitelist = map(ut.overlay_ip, whitelist)
        rules[src] = whitelist

    return rules
    

def config_controller(dest_path, rules):
    """
    Arguments:
        dest_path:- Should be a remote path, 
            e.g. ubuntu@10.0.0.1:/home/ubuntu
        rules:- a topology map between dest addr and
            acceptable source
    """

    FILENAME = "./topo.p"
    #write to file
    with open(FILENAME, 'wb') as topo:
        pickle.dump(rules, topo, protocol=pickle.HIGHEST_PROTOCOL)

    #copy file to controller
    scp_cmd = "scp {} {}".format(FILENAME, dest_path)
    os.system(scp_cmd)

    #delete local tmp file
    os.remove(FILENAME)


if __name__ == "__main__":
    orc = Orc(mesh=True)
    topo = orc.virt_topology
    nodes = orc.get_topology()
    rules = get_rules(topo, nodes)

    print topo
    #print nodes
    print rules

    #contr_path = "ubuntu@{}:/home/ubuntu".format(ut.extract_ip(config.contr_addr))
    #config_controller(contr_path, rules)
