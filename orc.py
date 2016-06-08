from topology import topology, nodes
import config
from servers import ServerManager
import pdb
import time
import sys
import paramiko
from socket import error as socket_error
from utils.vino_utils import extract_ip, SleepFSM
#NOTE: Currently only single region deployment/ deletion 
#is supported; 

class Orc(object):
    """
    Derived from ViNO. 
    Changes: -Drops advanced config params 
    from the topology and config files
    All nodes are treated as switches, since its functionality is a 
    superset of that of hosts
    """
    def __init__(self, mesh=False):
        """
        Infers topology and node properties
        and instantiates helper classes

        Arguments:- 
            mesh- whether to create a complete 
                graph of all the nodes
        """
        self.mesh = mesh
        if mesh:
            #In mesh mode, the actual topology is a complete mesh
            #However, we also need the intended overlay topology, i.e.
            #the virt_topology
            self.topology = self._mesh_topology(nodes)
            self.virt_topology = self._complete_topology(topology)
        else:
            self.topology = self._complete_topology(topology)
        self.nodes = self._get_nodes(self.topology, nodes)
        
        self.server_manager = ServerManager(config.username, config.password,
            config.region, config.tenant)
        self.sleep = SleepFSM()

    def _complete_topology(self, topology):
        """
        walks through the topology dict and 
        adds info about all nodes, including 
        bidirectional connections in the corresponding node
        otherwise the vxlan tunnels are only one-way

        Returns:-
            {node_1 -> set(node_x, node_y, ...)}

        """
        #The completed topology
        complete = {}
        for node, connections in topology.items():
            #add the current node, if not in dict
            if node not in complete: 
                complete[node] = set()

            #iterate over connections, and add them 
            for connection in connections:
                #add the connection to the current node's list of 
                #connections
                complete[node].add(connection)
                #add the connection to the dict if not in complete
                if connection not in complete:
                    complete[connection] = set()
                #add the current node to this node's connections    
                complete[connection].add(node)

        return complete

    def _mesh_topology(self, nodes):
        """
        Similar to _complete_topology.
        Returns a complete graph of nodes
        """
        complete = {}
        node_names = nodes.keys()
        for idx in range(len(node_names)):
            complete[node_names[idx]] = node_names[:idx] + node_names[idx+1:]
            
        return complete

    def _get_nodes(self, topology, nodes):
        """
        Get all the required properties of the nodes
        """
        node_maps = {}
        for node in topology:
            node_dict = {}
            node_dict['name'] = config.instance_prefix + node
            node_dict['region'] = nodes[node].get('region',  config.region)
            #The image can be the image name or id (UUID with hyphens)
            node_dict['image'] = nodes[node].get('image', config.image)
            node_dict['flavor'] = nodes[node].get('flavor', config.flavor)
            node_dict['contr_addr'] = config.contr_addr
            node_dict['vm_username'] = nodes[node].get('vm_username', config.vm_username)

            #secgroups can be specified as single string or as [str]
            secgroups = nodes[node].get('secgroups', config.secgroups)
            if type(secgroups) != list:
                secgroups = [secgroups]
            node_dict['secgroups'] = secgroups 
            node_maps[node] = node_dict

        return node_maps

    def create_instances(self):
        """
        Create the instance specified in the nodes dict
        """
        for node_name, node in self.nodes.items():
            print "creating {} in {}".format(node_name, node['region'])
            node_id = self.server_manager.create_server(node['name'], node['image'], 
                node['flavor'], key_name=config.key, region_name=node['region'], 
                secgroups = node['secgroups'])
            #Add the node id to the node dict
            node['id'] = node_id
            node['status'] = 'BUILD'

    def wait_until_built(self):
        """
        Loops until servers are not in BUILD state 
        """
        self.sleep.init()
        while True:
            in_progress = [(name, node) for name, node in self.nodes.items() 
                                    if node['status'] == 'BUILD']
            in_progress_count = len(in_progress)
            print "waiting for {}/{} nodes ...".format(in_progress_count, len(self.nodes))
            for node_name, node in in_progress: 
                server = self.server_manager.get_server(
                    server_id=self.nodes[node_name]['id'], parse=False)
                if server['status'] != 'BUILD':
                    #Check for errors 
                    if server['status'] != 'ACTIVE':
                        #quit, something wonky-happend
                        print "ERROR: Status of {} is {}".format(node_name, server['status']) 
                        sys.exit(1)
                    node['status'] = server['status'] 
                    
                    node_net, node_nics = server['addresses'].popitem()
                    node['addr'] = node_nics[0]['addr'] 
                    node['net'] = node_net
                    node['name'] = server['name'] #instance name

                    print "{} changed to {}".format(node_name, server['status'])
                    in_progress_count -= 1
            
            if in_progress_count == 0: 
                break
            self.sleep()
    
    def wait_until_sshable(self):
        """
        Loop until all servers are SSH-able
        """
        sshClient = paramiko.SSHClient()
        sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sleep.init()
        #Assume all nodes are un-SSH-able
        not_sshable = self.nodes.values()
        while len(not_sshable) > 0:
            #get the node from the list of nodes not ssh-able
            node = not_sshable.pop()
            while True: 
                #keep trying this node
                #critical path is through slowest node
                #no point trying other nodes
                try:
                    print "Trying ssh {}@{}".format(node['vm_username'], node['addr'])
                    sshClient.connect(node['addr'], username=node['vm_username'])
                    break
                except socket_error:
                    print "SSH failed...."
                self.sleep()
                
    def config_vxlan(self):
        """
        Setup vxlan on the nodes
        """
        #Need to import here, otherwise 
        #will lead to cyclic dependencies
        #since setup_ovs import orc
        from setup_ovs import setup_ovs_swarm
        setup_ovs_swarm(topology=self.topology, nodes=self.nodes)

    def config_controller(self):
        """
        Config the controller by syncing
        the topology and node IPs to the controller
        """
        import sdn_controller
        contr_path = "ubuntu@{}:/home/ubuntu".format(extract_ip(config.contr_addr))
        rules = sdn_controller.get_rules_from_topology(self.virt_topology, self.nodes)
        sdn_controller.config_controller(contr_path, rules) 

    def create_topology(self, setup_overlay=True):
        """
        High level method that calls other methods
        to create the topology
        This is typically the main 
        entry point for node and topology creation
        """
        #provision the VMs
        self.create_instances()
        self.wait_until_built()
        self.wait_until_sshable()

        if setup_overlay:
            #create the VXLAN overlay tunnels
            self.config_vxlan()
            
            #config the controller 
            #to enforce the topology
            if self.mesh:
                self.config_controller()

    def get_topology(self, server_name=None, server_prop=None):
        """
        Gets info about all instance in topology
        """
        #TODO: support server_name, server_prop

        return self.server_manager.get_servers(name_prefix=config.instance_prefix) 

    def delete_topology(self):
        """
        deletes entire topology by matching on prefix
        NOTE: this may delete unwanted instances if the 
        prefix matches
        """
        self.server_manager.delete_servers(name_prefix=True, name=config.instance_prefix)


if __name__ == "__main__":
    orc = Orc(mesh=True)
    print orc.topology
    #orc.create_topology()
    #orc.delete_topology()
    #orc.config_vm()
