#/bin/bash

#params:-
#bridge- name of bridge
#contr_addr- controller address
#int_port- internal port that is added
#int_ip - internal ip of this node
#vni- vni between this and other host
#remote_ip - ip of other node (i.e. on the other side of the tunnel)

#Add bridge
sudo ovs-vsctl add-br {{ bridge }}

sudo ovs-vsctl set-fail-mode {{ bridge }} standalone

#add internal port
sudo ovs-vsctl add-port {{ bridge }} {{ int_port }} -- set interface {{ int_port }} type=internal

mac=`sudo ovs-vsctl get interface {{ int_port }} mac_in_use` && sudo ovs-vsctl set interface {{ int_port }} mac=\"$mac\"

sudo ifconfig {{ int_port }} {{ int_ip }}/24 up

#setup vxlan connections
{% for conn in connections %}
sudo ovs-vsctl add-port {{ bridge }} vxlan{{ loop.index }} -- set interface vxlan{{ loop.index }} type=vxlan options:remote_ip={{ conn.remote_ip }} options:key={{ conn.vni }}
{% endfor %}
