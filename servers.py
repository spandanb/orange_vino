from auth import Auth
import requests
import pdb
import json
from utils import is_prefix, is_uuid, SleepFSM
import consts
import os
import pprint
import paramiko
from socket import error as socket_error

#TODO:remove all region_name in each method
#instead when changing region call `change_params`

class ServerManager(object):
    """
    Manages booting instances
    NOTE: need to account for various exceptions:
        -over limit
        -token expired/unauthenticated etc.
    Should handle, adding secrules/secgroups, creating keys across regions
    """
    def __init__(self, username, password, region_name=None, tenant_name=None):
        self.auth = Auth()
        self.service_catalog = self.auth(username, password, tenant_name=tenant_name)
        self.token = self.auth.tenant_token
        self.region_name = region_name
        self.tenant_name = tenant_name

    def change_params(self, region_name=None, tenant_name=None):
        """
        Used to change default tenant_name and/or region_name
        """
        if region_name:
            self.region_name = region_name
        if tenant_name:
            self.tenant_name = tenant_name
            self.auth(tenant_name=tenant_name)
            self.token = self.auth.tenant_token

    def _get_service_url(self, service_name, region):
        """
        get public url of service in region
        """
        services = next(service for service in self.service_catalog
            if service['name'] == service_name)

        public_url = next(endpoint['publicURL'] for endpoint in services["endpoints"]
            if endpoint['region'] == region)

        return public_url

    def _call_api(self, service=None, api=None, api_url=None, region_name=None, verb="get", data=None):
        """
        helper method that wraps HTTP calls
        Parameters:
            service = [nova|neutron|...]
            api = "/servers/details"
            api_url = the url of the api
            region_name = [CORE | EDGE-TR-1 | ...]
            verb = [get | post ]
            params = parameters associated with post
        """
        #either service + api, or api_url must be specified
        if not(service and api) and not api_url:
            raise ValueError("Invalid api endpoint parameters specified")

        if not api_url:
            region_name = region_name or self.region_name
            api_url = self._get_service_url(service, region_name) + api

        #print "api_url is {}, data is {}, verb is {}".format(api_url, data, verb)
        headers = {"X-Auth-Token" : self.token}
        if verb == "get":
            if data:
                resp = requests.get(api_url, headers=headers,
                    params=data)
            else:
                resp = requests.get(api_url, headers=headers)
        elif verb == "post":
            headers["Content-Type"] = "application/json"
            resp = requests.post(api_url, headers=headers,
                data=json.dumps(data))
        elif verb == "delete":
            resp = requests.delete(api_url, headers=headers)

        #if the version of API is not specified, e.g.
        #the service catalog for EDGE-TR-1 for glance returns
        #an unversioned url
        if resp.status_code == 300 and resp.reason == 'Multiple Choices':
           api_url = resp.json()['versions'][0]['links'][0]['href'] + api
           resp = self._call_api(api_url=api_url, verb=verb, data=data)

        if resp.status_code > 204:
            raise ValueError("Error: {}: {}\nRequest url was {}\n{}".format(resp.status_code,
                resp.reason, resp.url, resp.text))

        return resp

    def _image_ref(self, name, region_name=None):
        """
        returns id of image with matching name
        """
        region_name = region_name or self.region_name
        resp = self._call_api(service="nova", api="/images", data={'name': name},
            region_name=region_name)
        images = resp.json()["images"]
        try:
            return next(image['id'] for image
                in images if image['name'] == name)
        except StopIteration:
            raise ValueError("Image {} not found".format(name))

    def _flavor_ref(self, name, region_name=None):
        """
        returns id of flavor with matching name
        """
        region_name = region_name or self.region_name
        resp = self._call_api(service="nova", api="/flavors", region_name=region_name)
        flavors = resp.json()["flavors"]
        try:
            return next(flavor['id'] for flavor
                in flavors if flavor['name'] == name)
        except StopIteration:
            raise ValueError("Flavor {} not found".format(name))

    def _parse_server_details(self, server):
        """
        helper method to extract server details
        NOTE: this may not be appropriate in all cases
        """
        if server["status"] != "ACTIVE":
            return server
        #Get first network addresses
        addr_name, addr_prop = server["addresses"].popitem()
        #a list- perhaps to account for multiple interfaces
        addr_prop = addr_prop[0]
        return {
            "addr" : addr_prop["addr"],
            "id" : server["id"],
            "name" : server["name"]
        }

    def get_servers(self, parse=True, name_prefix=None, select=None, region_name=None):
        """
        Gets the information about all servers
        Arguments:
            parse- parse each server, and only return some properties
            name_prefix- if specified, return array only has
                servers where name is a prefix
            select- a function to filter servers by
        """
        """
        curl -H "X-Auth-Token: <Token ID>" http://iam.savitestbed.ca:5000/v2.0/servers/details
        """
        region_name = region_name or self.region_name

        resp = self._call_api(service="nova", api="/servers/detail", region_name=region_name)

        self.servers = resp.json()['servers']
        if parse:
            self.servers = map(self._parse_server_details, self.servers)
        if name_prefix:
            self.servers = filter(lambda server: is_prefix(name_prefix, server["name"]), self.servers)
        if select:
            self.servers = filter(select, self.servers)
        return self.servers

    def name_to_id(self, name, region_name=None):
        """
        Returns a list of server IDs with the given name
        """
        region_name = region_name or self.region_name
        select = lambda server: server['name'] == name
        servers = self.get_servers(select=select, region_name=region_name)
        return [s['id'] for s in servers]


    def create_server(self, name, image, flavor, region_name=None,
            key_name="", secgroups=[], secgroup_rules=[],
            user_data="", network=""):
        """
        Create a single server
        Either flavor or flavor_id should be specified
        Secgroup should already exist
        TODO: Handle the case where secgroup does not exist
        """
        region_name = region_name or self.region_name

        if is_uuid(image):
            image_ref = image
        else:
            #NOTE: getting the flavor ref can fail, maybe because of an inconsistent glance API
            #for multi-region case user should manually specify UUID for the flavor
            image_ref = self._image_ref(image, region_name=region_name)

        flavor_ref = self._flavor_ref(flavor, region_name=region_name)
        

        data = {
            "server": {
                "name": name,
                "imageRef": image_ref,
                "flavorRef": flavor_ref,
                "key_name": key_name,
                "user_data": user_data
            }
        }

        #Add secgroup
        if secgroups:
            data["server"]["security_groups"] = []
            for secgroup in secgroups:
                data["server"]["security_groups"].append(
                    {"name":  secgroup}
                )

        #Add network
        network_name = "{}-net".format(self.tenant_name)
        networks = self._call_api(service="nova", api="/os-networks").json()['networks']
        net_id = next(network['id'] for network in networks if network['label'] == network_name)
        data["server"]["networks"] = [{"uuid": net_id}]



        resp = self._call_api(service="nova", api="/servers", verb="post", data=data,
            region_name=region_name)
        return resp.json()['server']['id']

    def get_server(self, server_id=None, name=None, parse=True):
        """
        Get details about server; lookup based
        on either id or name
        """
        if server_id:
            server = self._call_api(service="nova", api="/servers/"+server_id).json()['server']
            if parse:
                return self._parse_server_details(server)
            else:
                return server

        elif name:
            return next(server for server in self.get_servers(parse=parse)
                if server["name"] == name)

    def delete_servers(self, server_id=None, name=None, name_prefix=False):
        """
        Delete one or more server(s) based on either name or id
        If name_prefix specified, delete all servers with 'name'
        as a prefix in their name
        """
        if server_id:
            self._call_api(service="nova", api="/servers/"+server_id,  verb="delete")
        elif name:
            for server in self.get_servers():
                #substring match
                if name_prefix and is_prefix(name, server["name"]): #server["name"].find(name) == 0:
                    self._call_api(service="nova", api="/servers/"+server["id"],  verb="delete")
                    print "deleting {}, {}".format(server["id"], server["name"])
                #Exact name match
                elif server["name"] == name:
                    print "deleting {}, {}".format(server["id"], server["name"])
                    self._call_api(service="nova", api="/servers/"+server["id"],  verb="delete")

    def get_keypairs(self):
        """
        Get information on all keypairs
        """
        return self._call_api(service="nova", api="/os-keypairs").json()["keypairs"]

    def remove_keypair(self, key_name):
        """
        deletes specified keypair
        """
        api = "/os-keypairs/{}".format(key_name)
        return self._call_api(service="nova", api=api, verb="delete")

    def create_keypair(self, key_name, public_key):
        """
        Creates a key pair if it doesn't exist

        Arguments:
            key_name: the key_name to create
            public_key: the string representing the public_key
        """
        keys = self._call_api(service="nova", api="/os-keypairs").json()["keypairs"]
        exists = next( (key for key in keys if key["keypair"]["name"] == key_name), False)
        if not exists:
            data = {"keypair": {"name": key_name, "public_key" : public_key}}
            new_key = self._call_api(service="nova", api="/os-keypairs", verb="post", data=data).json()

    def assign_floating_ip(self, server_id):
        """
        Assign floating IP
        """
        #List floating IPs; see if any are unassigned
        fips = self._call_api(service="nova", api="/os-floating-ips").json()['floating_ips']
        fip = next((fip for fip in fips if fip['fixed_ip'] == None), None)
        if fip:
            fip = fip["ip"]
        else:
            #Allocate a floating IP
            #Get name of floating IP pools
            resp = self._call_api(service="nova", api="/os-floating-ip-pools").json()
            fip_pool = resp['floating_ip_pools'][0]['name']
            resp = self._call_api(service="nova", api="/os-floating-ips", verb="post", data={"pool":fip_pool}).json()
            fip = resp["floating-ip"]["ip"]

        #Associate IP    
        api = "/servers/{}/action".format(server_id)
        data = {"addFloatingIp": {"address": fip}}
        resp = self._call_api(service="nova", api=api, verb="post", data=data)

    def wait_until_built(self, server_id):
        """
        Loops until server is not in BUILD state
        Returns it IP address
        """
        sleep = SleepFSM()
        sleep.init()
        while True:
            server = self.get_server(server_id = server_id, parse=False)
            if server['status'] != 'BUILD':
                #Check for errors
                if server['status'] != 'ACTIVE':
                    #quit, something wonky-happend
                    print "ERROR: Status of {} is {}".format(server_id, server['status'])
                    sys.exit(1)

                server_net, server_nics = server['addresses'].popitem()
                return server_nics[0]['addr']
                #server_net
                #node['name'] = server['name'] #instance name

            else:
                sleep()

    def wait_until_sshable(self, server_id, username=''):
        """
        Waits until server is SSH'able
        Returns IP address
        """
        username = username or 'ubuntu'
        ipaddr = self.wait_until_built(server_id)

        sshClient = paramiko.SSHClient()
        sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sleep = SleepFSM()
        sleep.init()

        while True:
            try:
                print "Trying ssh {}@{}".format(username, ipaddr)
                sshClient.connect(ipaddr, username=username)
                break
            except socket_error:
                print "SSH failed...."
                sleep()

        return ipaddr

def print_resp(resp):
    """
    prints the response object
    """

    #The print function to use
    prnt = pprint.pprint

    if hasattr(resp, 'json'):
        prnt(resp.json())
    else:
        prnt(resp)
        


if __name__ == "__main__":
    server_manager = ServerManager(os.environ["OS_USERNAME"],
                                   os.environ["OS_PASSWORD"],
                                   os.environ["OS_REGION_NAME"],
                                   os.environ["OS_TENANT_NAME"])
    #List servers
    #pprint.pprint(server_manager.get_servers())

    #List flavors
    #pprint.pprint(server_manager._call_api(service="nova", api="/flavors").json())

    #List images
    #pprint.pprint(server_manager._call_api(service="nova", api="/images").json())

    #List keypairs
    #pprint.pprint(server_manager._call_api(service="nova", api="/os-keypairs").json())

    #Create a server
    #server_manager.create_server(name, image, flavor, key_name='', secgroups=['default'])
    
    server_id = server_manager.create_server("span-vm-1", "Ubuntu1404-64", "m1.small", key_name='key_spandan', secgroups=['default', 'spandantb'])
    server_manager.wait_until_built(server_id)
    server_manager.assign_floating_ip(server_id)

    #List networks
    #print_resp(server_manager._call_api(service="nova", api="/os-networks"))

