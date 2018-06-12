#!/usr/bin/env python
import os
import sys
import json
import requests
import ConfigParser
import optparse
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class nifiregistycon(object):
    def __init__(self, url, username, password, user):
        self.url = url + '/nifi-registry-api/'
        self.username = username
        self.password = password
        self.token = self.rest('access/token',  method='post', formatjson=False)
        if not self.userexists(user):
            self.adduser(user)

    def rest(self, endpoint, data=None, method='get', params=None, token=None, formatjson=True,):
        url = self.url + endpoint
        if token:
            headers = {"Authorization": "Bearer %s" % (token), "Content-Type": "application/json"}
            try:
                r = requests.request(method, url, headers=headers, verify=False, data=data, params=params)
            except:
                print("Cannot connect to Nifi")
                sys.exit(1)
        else:
            try:
                r = requests.request(method, url, auth=(self.username, self.password), verify=False, data=data, params=params)
            except:
                print("Cannot connect to Nifi")
                sys.exit(1)

        if formatjson:
            return(json.loads(r.text))
        else:
            return(r.text)

    def userexists(self, user):
        listofusers = [x['identity'] for x in self.rest('tenants/users', token=self.token)]
        if user in listofusers:
            return(True)
        else:
            return(False)

    def adduser(self, user):
        data = {"identity": user, "resourcePermissions": {"anyTopLevelResource": {"canRead": True, "canWrite": True, "canDelete": True},
                "buckets": {"canRead": True, "canWrite": True, "canDelete": True},
                "tenants": {"canRead": False, "canWrite": False, "canDelete": False},
                "policies": {"canRead": False, "canWrite": False, "canDelete": False},
                "proxy": {"canRead": True, "canWrite": True, "canDelete": True}}}
        self.rest('tenants/users', formatjson=False,  method='post', token=self.token, data=json.dumps(data))


def main():
    hostname = os.popen("hostname -f").read().strip()
    parser = optparse.OptionParser(usage="usage: %prog [options]")
    parser.add_option("-c", "--configs", dest="configs", default="./configs", help="Configs file to read")
    parser.add_option("-a", "--usertoadd", dest="user", default=hostname, help="User name to add, default is the system's hostname")
    (options, args) = parser.parse_args()
    Config = ConfigParser.ConfigParser()
    Config.read(options.configs)
    if Config.getboolean("NifiRegistry", "enabled"):
        nifiregistycon(Config.get("NifiRegistry", "url"), Config.get("NifiRegistry", "username"), Config.get("NifiRegistry", "password"), options.user)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nAborting ... Keyboard Interrupt.")
        sys.exit(1)
