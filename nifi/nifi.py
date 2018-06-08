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


class nificon(object):
    def __init__(self, protocol, host, port, username, password):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.token = self.rest('nifi-api/access/token', method='post', headers={"Content-Type": "application/x-www-form-urlencoded"}, data="username=%s&password=%s" % (self.username, self.password), formatjson=False)

    def rest(self, endpoint, data=None, method='get', params=None, token=None, headers={"Accept": "application/json", "Content-Type": "application/json"}, formatjson=True,):
        url = self.protocol + "://" + self.host + ":" + str(self.port) + "/" + endpoint
        if token:
            headers.update({"Authorization": "Bearer %s" % (token)})
        try:
            r = requests.request(method, url, headers=headers, verify=False, data=data, params=params)
        except:
            print("Cannot connect to Nifi")
            sys.exit(1)
        if formatjson:
            return(json.loads(r.text)) else:
            return(r.text)

    def sslcontext(self, keystore, keystorepassword, keypassword, keystoretype, truststore, truststorepassword, truststoretype):
        data = {"revision":{"clientId":"Cloudbreak Script","version":0},"component":{"type":"org.apache.nifi.ssl.StandardSSLContextService","bundle":{"group":"org.apache.nifi","artifact":"nifi-ssl-context-service-nar","version":"1.5.0.3.1.1.0-35"},"name":"StandardSSLContextService"}}
        processorid = self.rest('nifi-api/controller/controller-services', token=self.token, data = json.dumps(data), method = 'POST')['id']
        data = {"component":{"id": processorid,"name":"StandardRestrictedSSLContextService","comments":"","properties":{"Keystore Filename": keystore ,"Keystore Password": keystorepassword ,"key-password": keypassword,"Keystore Type": keystoretype, "Truststore Filename": truststore,"Truststore Password": truststorepassword,"Truststore Type": truststoretype}},"revision":{"clientId":"Cloudbreak Script","version":1}}
        self.rest('nifi-api/controller-services/%s' % (processorid), data=json.dumps(data), method='put', token=self.token)
        data = {"revision":{"clientId":"Cloudbreak Script","version": 2},"component":{"id":processorid,"state":"ENABLED"}}
        self.rest('nifi-api/controller-services/%s' % (processorid), data=json.dumps(data), method='put', token=self.token)
        return(processorid)

    def addatlas(self, atlasurl, atlasusername, atlaspassword, kafkaurl, kakfaprotocol, kafkakerberosservicenamekafka, nifikerberosprincipal, nifikerberoskeytab, sslcontext):
        data = {"revision":{"clientId":"Cloudbreak Script","version":0},"component":{"type":"org.apache.nifi.atlas.reporting.ReportLineageToAtlas","bundle":{"group":"org.apache.nifi","artifact":"nifi-atlas-nar","version":"1.5.0.3.1.1.0-35"}}}
        processorid = self.rest('nifi-api/controller/reporting-tasks', token=self.token, data = json.dumps(data), method = 'POST')['id']
        data = {"component":{"id":processorid,"name":"ReportLineageToAtlas",
        "schedulingStrategy":"TIMER_DRIVEN","schedulingPeriod":"5 mins","comments":"",
        "state":"RUNNING","properties":{"atlas-urls": atlasurl,"atlas-username": atlasusername ,
        "atlas-password":"admin","atlas-conf-dir":"/etc/nifi/conf",
        "atlas-nifi-url": "%s://%s:%s/nifi" % (self.protocol, self.host, self.port),"atlas-default-cluster-name":"nifi",
        "ssl-context-service": sslcontext,"atlas-conf-create":"true","kafka-bootstrap-servers": kafkaurl,
        "nifi-kerberos-principal":nifikerberosprincipal, "kafka-kerberos-service-name-kafka" : kafkakerberosservicenamekafka, "nifi-kerberos-keytab":nifikerberoskeytab}},"revision":{"clientId":"Cloudbreak Script","version":0}}
        reply = self.rest('nifi-api/reporting-tasks/%s' % (processorid), data=json.dumps(data), method='put', token=self.token, formatjson=False)
        data = {"revision":{"clientId":"Cloudbreak Script","version":1},"component":{"id": processorid,"state":"RUNNING"}}
        self.rest('nifi-api/reporting-tasks/%s' % (processorid), method='put', data=json.dumps(data), token=self.token, formatjson=False)

    def addregistry(self, url):
        data = {"revision":{"Cloudbreak Script","version":0},"component":{"name":"registry","uri": url, "description":"Central Nifi Registry Added by Cloudbreak"}}
        self.rest('nifi-api/controller/registry-clients', method='post', data=json.dumps(data), token=self.token)


def main():
    parser = optparse.OptionParser(usage="usage: %prog [options]")
    parser.add_option("-S", "--protocol", dest="protocol", default="http", help="default is http, set to https if required")
    parser.add_option("-P", "--port", dest="port", default="9090", help="Set Ranger port")
    parser.add_option("-u", "--username", dest="username", default="admin", help="Ranger Username")
    parser.add_option("-p", "--password", dest="password", default="admin", help="Ranger Password")
    parser.add_option("-H", "--host", dest="host", default="localhost", help="Ranger Host")
    parser.add_option("-c", "--configs", dest="configs", default="./configs", help="Nifi repo to adjust")
    (options, args) = parser.parse_args()
    username = options.username
    password = options.password
    port = options.port
    protocol = options.protocol.lower()
    host = options.host
    Config = ConfigParser.ConfigParser()
    Config.read(options.configs)
    nifi = nificon(protocol, host, port, username, password)
   if Config.getboolean("Nifi", "sslenabled"):
        sslcontext = nifi.sslcontext(Config.get("Nifi", "sslkeystore"), Config.get("Nifi", "sslkeystorepassword"), Config.get("Nifi", "sslkeypassword"), Config.get("Nifi", "sslkeystoretype"), Config.get("Nifi", "ssltruststore"), Config.get("Nifi", "ssltrustpassword"), Config.get("Nifi", "truststoretype"))
    else:
        sslcontext = None
    if Config.getboolean("Atlas", "enabled"):
        if Config.getboolean("Nifi", "kerberosenabled"):
            nifikerberoskeytab = Config.get("Nifi","nifikerberosprincipal")
            nifikerberosprincipal = Config.get("Nifi","nifikerberoskeytab")
            kafkakerberosservicenamekafka = Config.get("Kafka", "kafka-kerberos-service-name-kafka")
        else:
            nifikerberoskeytab = None
            nifikerberosprincipal = None
            kafkakerberosservicenamekafka = None
        nifi.addatlas(Config.get("Atlas", "atlasurl"), Config.get("Atlas", "atlasusername"), Config.get("Atlas","atlaspassword"), Config.get("Kafka","kafkaurl"), Config.get("Kafka","kakfaprotocol"), kafkakerberosservicenamekafka, nifikerberoskeytab, nifikerberosprincipal, sslcontext)
    if Config.getboolean("NifiRegistry", "enabled"):
        nifi.addregistry(Config.get("NifiRegistry","url"))



if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nAborting ... Keyboard Interrupt.")
        sys.exit(1)
