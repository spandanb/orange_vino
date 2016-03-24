import requests
import json 
import consts
import pdb

class Auth(object):
    """
    Authenticates user and returns service catalog 
    
    Typical usage:
    auth(username, password, region_name, tenant_name)
    """
    def __init__(self):
        self.token = None
        self.tenant_token = None
        self.default_tenant = None
        #Returned after successful auth, members include serviceCatalog and token
        self.access = None  
        self.service_catalog = None
        self.region_service_catalog = None

    def __call__(self, *credentials, **kw_credentials):
        return self.auth(*credentials, **kw_credentials)

    def _keystone_url(self, suffix):
        """
        Return URL for a specific keystone API 
        """
        return consts.KEYSTONE_URL + suffix

    def _get_token(self, access):
        return access['token']['id']

    def _get_service_catalog(self, access):
        return access["serviceCatalog"]

    def credentials_auth(self, username, password):
        """
        authenticate the user with username and password
        """
        """
        curl -d '{"auth":{"passwordCredentials":{"username": username, 
            "password": password},"tenantName": tenant}}' 
            -H "Content-Type: application/json" 
            http://iam.savitestbed.ca:5000/v2.0/tokens
        """
        data = {
            "auth":{
                "passwordCredentials": {
                    "username":username,
                    "password":password
                },
            }
        }

        headers = {"Content-Type": "application/json"}
        
        resp = requests.post(self._keystone_url("tokens"), data=json.dumps(data), 
            headers=headers )
        if resp.status_code > 204:
            self.resp = resp
            raise ValueError("Error: {} {}".format(resp.status_code, resp.reason))
        
        self.access = resp.json()['access']
        self.token = self._get_token(self.access)

    def tenant_auth(self, tenant_name=None):
        """
        authenticate the user for a specific tenant
        """
        if not tenant_name and not self.default_tenant:
            #If no tenant specified get the first tenant
            self.get_tenants()
            tenant_name = self.tenants[0]

        self.default_tenant = tenant_name 

        data = {
            "auth":{
                "token": {
                    "id": self.token
                },
                "tenantName": tenant_name
            }
        }
        headers = {"Content-Type": "application/json"}
        resp = requests.post(self._keystone_url("tokens"), data=json.dumps(data), 
            headers=headers )
        if resp.status_code > 204:
            self.resp = resp
            raise ValueError("Error: {} {}".format(resp.status_code, resp.reason))
        
        self.access = resp.json()['access']
        self.tenant_token = self._get_token(self.access)
        self.service_catalog = self._get_service_catalog(self.access)

    def get_tenants(self):
        """
        gets the available tenants for this token
        """
        headers = {
                "X-Auth-Token": self.token
            }    
        resp = requests.get(self._get_url("tenants"),
            headers=headers)
        tenant_dicts = resp.json()['tenants']
        #Extract the names
        tenants = [tenant_dict['name'] for tenant_dict in tenant_dicts ]
        self.tenants = tenants
        return tenants 

    def filter_service_catalog(self, region_name):
        """
        filter service catalog for specific region
        """
        """
        a service catalog is a list of services,
        where each service has keys: endpoints_links, 
        endpoints, type, name
        """
        self.region_service_catalog = []
        for service in self.service_catalog:
            filtered_service = {"name": service["name"],
                "type": service["type"], "endpoints_links": service["endpoints_links"]}
            filtered_service["endpoints"] = \
                filter(lambda endpoint: endpoint["region"] == region_name, 
                service["endpoints"])
            self.region_service_catalog.append(filtered_service)

    def auth(self, *credentials, **kw_credentials):
        """
        Expected kw arguments must be one of:
            username, password, tenant_name, region_name
        
        First call must specify username and password
        once user is authenticated, subsequent calls, can specify 
        region_name and/or tenant_name to receive a new service catalog 
        
        Returns region-specific service catalog
        """
        valid_params = ["username", "password", "region_name", "tenant_name"] 
        params = {"username": None, "password": None, "region_name":None,
            "tenant_name": None}
        
        #Parse positional arguments
        if len(credentials) > 4:
            raise ValueError("Invalid number of arguments. Specify atmost 4 arguments:")

        for idx, value in enumerate(credentials):   
            params[valid_params[idx]] = credentials[idx] 
        
        #Parse keyword arguments
        for key, value in kw_credentials.items():
            #Check if the key is valid
            if key not in valid_params:
                raise ValueError("Invalid paramter: {}"
                       "Valid parameters are {}, {}, {}, {}").format(key, *valid_params)
            #Check if the key has not already been specified
            if params[key]:
                raise ValueError("{} already specified through positional argument".format(key))
            else:
                params[key] = value
      
        #TODO: Tokens can expire
        if params["username"] and params["password"]:
            self.credentials_auth(params["username"], params["password"])

        if params["tenant_name"]:# and params["tenant_name"] != self.default_tenant:
            self.tenant_auth(tenant_name=params["tenant_name"])


        if params["region_name"]: #and params["region_name"] != self.default_region:
            self.filter_service_catalog(params["region_name"])
        
        #return either the filter or unfiltered catalog
        return self.region_service_catalog or self.service_catalog 

if __name__ == "__main__":
    pass
