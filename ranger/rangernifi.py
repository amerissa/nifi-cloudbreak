#!/usr/bin/env python
import os
import sys
import json
import requests
import optparse
import uuid
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



class rangercon(object):
    def __init__(self, protocol, host, port, username, password, repo):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.repo = repo

    def rest(self, endpoint, data=None, method='get', formatjson=True, params=None):
        url = self.protocol + "://" + self.host + ":" + str(self.port) + "/" + endpoint
        header = {"Accept": "application/json", "Content-Type": "application/json"}
        try:
            r = requests.request(method, url, headers=header, auth=(self.username, self.password), verify=False, data=data, params=params)
        except:
            print("Cannot connect to Ranger")
            sys.exit(1)
        if formatjson:
            return(json.loads(r.text))
        else:
            return(r.text)

    def userexists(self, user):
        listofusers = [v for v in self.rest('service/xusers/users')['vXUsers']]
        if user in listofusers:
            return(True)
        else:
            return(False)
    def adduser(self, user):
        data = {"groupIdList":None, "status":1, "userRoleList":["ROLE_USER"], "name":user, "password":  uuid.uuid4().hex, "firstName":user,"lastName":user,"emailAddress":""}
        self.rest('service/xusers/secure/users', data=json.dumps(data), method='POST', formatjson=False)

    def executeuser(self, user):
        exists = self.userexists(user)
        if not exists:
            self.adduser(user)

    def checkrepo(self):
        self.repoinfo = [v for v in self.rest('service/plugins/services')['services'] if v['name'] == self.repo][0]
        if self.repoinfo:
            return(True)
        else:
            return(False)

    def appendtopolicy(self, user):
       exists = self.checkrepo()
       if exists:
           repoid = self.repoinfo['id']
           policyid = [ v['id'] for v in self.rest('service/plugins/policies/service/' + str(repoid))['policies'] if v['name'] == "all - nifi-resource" ][0]
           policyinfo = self.rest('service/plugins/policies/' + str(policyid))
           if not policyinfo['policyItems']:
               items = {"users":[user],"accesses":[{"type":"READ","isAllowed": True},{"type":"WRITE","isAllowed": True}]}
               policyinfo['policyItems'].append(items)
               self.rest('service/plugins/policies/' + str(policyid), method='put', data=json.dumps(policyinfo))
           else:
              if  user not in policyinfo['policyItems'][0]['users']:
                   policyinfo['policyItems'][0]['users'].append(user)
                   self.rest('service/plugins/policies/' + str(policyid), method='put', data=json.dumps(policyinfo))


def main():
    hostname = os.popen("hostname -f").read().strip()
    parser = optparse.OptionParser(usage="usage: %prog [options]")
    parser.add_option("-S", "--protocol", dest="protocol", default="http", help="default is http, set to https if required")
    parser.add_option("-P", "--port", dest="port", default="6080", help="Set Ranger port")
    parser.add_option("-u", "--username", dest="username", default="admin", help="Ranger Username")
    parser.add_option("-p", "--password", dest="password", default="admin", help="Ranger Password")
    parser.add_option("-H", "--host", dest="host", default="localhost", help="Ranger Host")
    parser.add_option("-a", "--usertoadd", dest="user", default=hostname, help="User name to add, default is the system's hostname")
    parser.add_option("-n", "--nifi-repo", dest="nifirepo", default="nifi", help="Nifi repo to adjust")
    (options, args) = parser.parse_args()
    username = options.username
    password = options.password
    port = options.port
    protocol = options.protocol.lower()
    host = options.host
    user = options.user
    nifirepo = options.nifirepo
    ranger = rangercon(protocol, host, port, username, password, nifirepo)
    ranger.executeuser(user)
    ranger.appendtopolicy(user)
if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nAborting ... Keyboard Interrupt.")
        sys.exit(1)
