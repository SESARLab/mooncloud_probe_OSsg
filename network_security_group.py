__author__ = 'Patrizio Tufarolo'
__email__ = 'patrizio.tufarolo@studenti.unimi.it'


import time
import uuid
import subprocess

from testagent.probe import Probe

from neutronclient.v2_0.client import Client as NeutronClient
from novaclient.client import Client as NovaClient
from keystoneauth1.identity import v3 as KeystoneClient
from keystoneauth1 import session as KeystoneSession

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

from celery.contrib import rdb

class NetworkSecurityGroup(Probe):
    def nullRollback(self,inputData):
        return inputData

    def createNeutronClient(self,inputData):
        self.keystonecl = KeystoneClient.Password(auth_url=self.testinstances["OpenStackConfig"]["OS_AUTH_URL"],
                        username=self.testinstances["OpenStackConfig"]["OS_USERNAME"],
                        password=self.testinstances["OpenStackConfig"]["OS_PASSWORD"],
                        project_id=self.testinstances["OpenStackConfig"]["OS_PROJECT_ID"],
                        user_domain_name=self.testinstances["OpenStackConfig"]["OS_USER_DOMAIN_NAME"])
        sess = KeystoneSession.Session(auth=self.keystonecl)
        self.novacl = NovaClient(2,session=sess)
        self.neucl = NeutronClient(session=sess)
        return inputData


    def deployHoneypot(self,inputData):
        name = "honeypot_" + str(uuid.uuid4())
        print("Deploying honeypot "+ str(name))
        imagename = self.testinstances["DeployHoneypot"]["Image"]
        print(imagename)
        flavorname = self.testinstances["DeployHoneypot"]["Flavor"]
        networkname = self.testinstances["DeployHoneypot"]["Network"]
        checktcp = self.testinstances["Configuration"]["CheckTCP"]
        checkudp = self.testinstances["Configuration"]["CheckUDP"]
        sgname = self.testinstances["DeployHoneypot"]["SecurityGroup"]

        openAllPorts = """#!/bin/bash\n"""
        if checktcp == "True":
            tcpminport = int(self.testinstances["Configuration"]["TCPMinPort"])
            tcpmaxport = int(self.testinstances["Configuration"]["TCPMaxPort"])
            openAllPorts += '''
            echo "Adding iptables TCP redirect\n"
            iptables -t nat -A PREROUTING -p tcp --dport '''+str(tcpminport)+':'+str(tcpmaxport-1)+' -j REDIRECT --to-ports '+str(tcpmaxport)+'''\n
            echo "Running TCP server in background on port '''+str(tcpmaxport)+'''\n"
            echo -e "import socket, sys; sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.bind(('','''+str(tcpmaxport)+''')); sock.listen(1); \nwhile True: s,a = sock.accept()\n" | python &
            \n'''

        if checkudp == "True":
            udpminport = int(self.testinstances["Configuration"]["UDPMinPort"])
            udpmaxport = int(self.testinstances["Configuration"]["UDPMaxPort"])
            openAllPorts += '''
            echo "Adding iptables UDP redirect"\n
            iptables -t nat -A PREROUTING -p udp --dport '''+str(udpminport)+':'+str(udpmaxport-1)+' -j REDIRECT --to-ports '+str(udpmaxport)+'''\n
            echo "Running python server in background on port''' + str(udpmaxport) + ''' udp\n"
            echo -e "import socket, sys; sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind((,'''+str(udpmaxport)+''')); \nwhile True: d,a = sock.recvfrom(4096)\n" | python &'''
        print openAllPorts
        image = self.novacl.images.find(name=imagename)
        flavor = self.novacl.flavors.find(name=flavorname)
        net = self.novacl.networks.find(label=networkname)
        server = self.novacl.servers.create(name,image,flavor,security_groups=[sgname],nics=[{'net-id': net.id}],userdata=openAllPorts)
        print("Deployed honeypot")
        print(server)
        self.server_id = server.id
        return inputData

    def removeHoneypot(self,inputData):
        print(self.novacl.servers.delete(self.server_id))
        print("Removed honeypot")
        return inputData

    def pollingHoneypot(self,inputData):
        try:
            timeout = time.time() + int(self.testinstances["DeployHoneypot"]["Timeout"]) or 120
        except:
            timeout = time.time() + 120
        status = self.novacl.servers.get(self.server_id).status
        while status == "BUILD":
            time.sleep(5)
            if timeout < time.time():
                raise Exception("Timeout!")
            status = self.novacl.servers.get(self.server_id).status
        if status != "ACTIVE":
            raise Exception("Failed to boot honeypot. Status is " + status + ". Please look at Openstack logs for more info.")
        print("Honeypot ready")
        return inputData


    def createFloatingIp(self,inputData):
        self.floating_ip = self.novacl.floating_ips.create(pool=self.testinstances['DeployHoneypot']['FloatingIPPool'])
        print("Created floating ip")
        return inputData

    def deleteFloatingIp(self,inputData):
        self.novacl.floating_ips.delete(self.floating_ip)
        print("Deleted floating ip")
        return inputData


    def attachFloatingIp(self,inputData):
        time.sleep(5)
        self.novacl.servers.get(self.server_id).add_floating_ip(self.floating_ip)
        return inputData
    def deattachFloatingIp(self,inputData):
        self.novacl.servers.get(self.server_id).remove_floating_ip(self.floating_ip)
        return inputData

    def parseSecurityGroup(self,inputData):
        allSecurityGroups = self.novacl.servers.get(self.server_id).list_security_group()
        allSecurityGroups_details = []
        for sg in allSecurityGroups:
            allSecurityGroups_details.append(self.neucl.show_security_group(str(sg)))
        print(allSecurityGroups_details)
        dict_tcp = {}
        dict_udp = {}
        list_tcp = []
        list_udp = []
        icmp = 0
        for sg in allSecurityGroups_details:
            for rule in sg['security_group']['security_group_rules']:
                if rule["direction"] == "ingress":
                    if rule["protocol"] == "icmp":
                        icmp = 1 if icmp == 0 else icmp

                    elif rule["port_range_min"] and rule["port_range_max"]:
                        for i in range(rule["port_range_min"],rule["port_range_max"]+1):
                            if self.testinstances["Configuration"]["CheckTCP"] and rule["protocol"] == "tcp" and i >= int(self.testinstances["Configuration"]["TCPMinPort"]) and i <= int(self.testinstances["Configuration"]["TCPMaxPort"]):
                                dict_tcp[i] = 1
                            if self.testinstances["Configuration"]["CheckUDP"] and rule["protocol"] == "udp" and i >= int(self.testinstances["Configuration"]["UDPMinPort"]) and i <= int(self.testinstances["Configuration"]["UDPMaxPort"]):
                                dict_udp[i] = 1
        if self.testinstances["Configuration"]["CheckTCP"]:
            print("Parsed TCP:")
            print(dict_tcp)
        if self.testinstances["Configuration"]["CheckUDP"]:
            print("Parsed UDP:")
            print dict_udp

        return icmp, dict_tcp, dict_udp

    def doRealScan(self,inputData):
        time.sleep(120)
        icmp_flag, dict_tcp, dict_udp = inputData
        def do_scan(target,options):
            command = ["/usr/bin/nmap", "-oX", "-"] + options + [str(target)]
            print("Executing nmap Command")
            print(command)
            output = subprocess.check_output(command)
            print output
            return NmapParser.parse(output)
        ip = str(self.floating_ip.ip)
        options = ""
        new_options = []
        if self.testinstances["NMapScan"]["Pn"] == "True":
            options += " -Pn"
            new_options.append("-Pn")

        if self.testinstances["Configuration"]["CheckTCP"] == "True":
            tcp_options = options + " -p"+self.testinstances["Configuration"]["TCPMinPort"]+"-"+self.testinstances["Configuration"]["TCPMaxPort"]+" -s"
            tcp_options += "S" if self.testinstances["NMapScan"]["TCPSynScan"] == "True" else "T"

            new_tcp_options = list(new_options)
            new_tcp_options.append("-p"+self.testinstances["Configuration"]["TCPMinPort"]+"-"+self.testinstances["Configuration"]["TCPMaxPort"])
            if self.testinstances["NMapScan"]["TCPSynScan"] == "True":
                new_tcp_options.append("-sS")
            else:
                new_tcp_options.append("-sT")

            tcpScanResults = do_scan(ip,new_tcp_options)
            print("tcpScanResults")
            print(tcpScanResults)
            for host in tcpScanResults.hosts:
                for port, protocol in host.get_open_ports():
                    if protocol == "tcp" and port not in dict_tcp:
                        return False


        if self.testinstances["Configuration"]["CheckUDP"] == "True":
            udp_options = options + " -p"+self.testinstances["Configuration"]["UDPMinPort"]+"-"+self.testinstances["Configuration"]["UDPMaxPort"]+" -sU"
            udpScanResults = do_scan(ip,udp_options)
            print("udpScanResults")
            print(udpScanResults)
            for host in udpScanResults.hosts:
                for port, protocol in host.get_open_ports():
                    if protocol == "udp" and port not in dict_udp:
                        return False

        return True


    def checkResult(self,inputData):
        self.deattachFloatingIp(inputData)
        self.deleteFloatingIp(inputData)
        self.removeHoneypot(inputData)
        return inputData

    def appendAtomics(self):
        self.appendAtomic(self.createNeutronClient,self.nullRollback)
        self.appendAtomic(self.deployHoneypot,self.removeHoneypot)
        self.appendAtomic(self.createFloatingIp,self.deleteFloatingIp)
        self.appendAtomic(self.attachFloatingIp,self.deattachFloatingIp)
        self.appendAtomic(self.pollingHoneypot,self.nullRollback)
        self.appendAtomic(self.parseSecurityGroup,self.nullRollback)
        self.appendAtomic(self.doRealScan,self.nullRollback)
        self.appendAtomic(self.checkResult,self.nullRollback)

probe = NetworkSecurityGroup()
