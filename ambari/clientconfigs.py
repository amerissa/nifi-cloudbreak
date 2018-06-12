#!/usr/bin/env python
import os
import sys
import json
import requests
import ConfigParser
import tarfile
import optparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ambariconn(object):
    def __init__(self, url, username, password):
        self.url = url
        self.username = username
        self.password = password
        self.name = self.clustername()
        self.downloadtar()

    def rest(self, endpoint, formatjson=True):
        url = self.url + '/' + endpoint
        header = {"X-Requested-By": "ambari"}
        try:
            r = requests.request('get', url, headers=header, auth=(self.username, self.password), verify=False)
        except:
            print("Cannot connect to Ambari" + self.url)
        if formatjson:
            return(json.loads(r.text))
        else:
            return(r.content)

    def clustername(self):
        clustername = self.rest('api/v1/clusters')['items'][0]["Clusters"]["cluster_name"]
        return(str(clustername))

    def downloadtar(self):
        url = 'api/v1/clusters/' + self.name + '/components?format=client_config_tar'
        data = self.rest(url, formatjson=False)
        file = open(self.name + '.tar.gz', 'wb')
        file.write(data)
        file.close()

    def extractar(self, dir):
        path = os.path.join(dir, self.name)
        if not os.path.exists(path):
            os.makedirs(path)
        tar = tarfile.open(self.name + '.tar.gz')
        tar.extractall(path=path)
        tar.close


def main():
    parser = optparse.OptionParser(usage="usage: %prog [options]")
    parser.add_option("-c", "--configs", dest="configs", default="./configs", help="Configs file defining ambari")
    parser.add_option("-d", "--directory", dest="dir", default="/etc/", help="Directory where to extract the tar files")
    (options, args) = parser.parse_args()
    Config = ConfigParser.ConfigParser()
    Config.read(options.configs)
    ambaris = Config.sections()
    for ambari in ambaris:
        try:
            am = ambariconn(Config.get(ambari, "url"), Config.get(ambari, "username"), Config.get(ambari, "password"))
        except:
            continue
        am.extractar(options.dir)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nAborting ... Keyboard Interrupt.")
        sys.exit(1)
