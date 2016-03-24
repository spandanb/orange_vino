This package allows booting VM and connecting them using overlays

PY Files
========
ansible_wrapper.py - provides a wrapper for ansible playbook execution
auth.py - handles authentication against SAVI keystone
consts.py
orc.py - reads topology.py to provision VMs and setup topology
setup_ovs.py - uses topology info + node IPs to create required 
    overlay tunnels
scli.py- command line like interface for underlay API
servers.py - handles CRUD operations on VM instances on SAVI testbed
sdn_controller.py
utils.py- provides some utility methods
vli.py- command line like interface for virtual networking API

Template and Playbook files
===========================
ansible.cfg- ansible default configuration
config_ovs_standalone.template.sh- a template for configuring OvS in standalone mode
config_ovs.template.sh - a template for configuring OvS
ovs_config_play.yaml

To create secure tunnels:
orc.create_topology()

Other Files
===========
env_vars.sh- specifies the env vars that must be set when using the underlay API
config.sample.py- sample config file
topology.sample.py- sample topology file

