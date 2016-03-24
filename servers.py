from auth import Auth
import requests
import pdb
import json
from utils import is_prefix, is_uuid
import consts
import os
import pprint

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
            raise ValueError("Error: {}: {}\nRequest url was {}".format(resp.status_code,
                resp.reason, resp.url))

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
            key_name=None, secgroups=[], secgroup_rules=[]):
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

        key_name = key_name or ""
        data = {
            "server": {
                "name": name,
                "imageRef": image_ref,
                "flavorRef": flavor_ref,
                "key_name": key_name,
            }
        }

        #Add secgroup
        if secgroups:
            data["server"]["security_groups"] = []
            for secgroup in secgroups:
                data["server"]["security_groups"].append(
                    {"name":  secgroup}
                )

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

    def create_keypair(self, key_name, public_key):
        """
        Creates a key pair if it doesn't exist

        Arguments:
            key_name: the key_name to create
            public_key: the string representing the public_key
        """
        keys = self._call_api(service="nova", api="/os-keypairs").json()["keypairs"]
        exists = next( (key for key in keys if key["name"] == key_name), False)
        if not exists:
            data = {"public_key" : public_key}
            new_key = self._call_api(service="nova", api="/os-keypairs", verb="post", data=data).json()


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

    #List secgroups
    pprint.pprint(server_manager._call_api(service="nova", api="/os-security-groups").json())

    #Create a server
    #server_manager.create_server(self, name, image, flavor, key_name='', secgroups=['default'])

