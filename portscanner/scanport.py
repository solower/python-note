#!/usr/bin/env python
#-*-encoding:UTF-8-*-
import json
import masscan
import nmap
import Queue
import threading

class Get_Portinfo(object):
    def __init__(self, destips, ports, rate=100):
        self.ports = ports
        self.destips = destips
        self.rate = rate
    
    def mas_scan(self):
        mas = masscan.PortScanner()
        ports = ','.join(self.ports)
        
        portinfo = {}
        for ips in self.destips:
            mas.scan(hosts = ips,ports=ports,arguments='--rate=%s' % self.rate)
            portinfo[ips] = mas.scan_result['scan']
        return portinfo    
     
    def format(self):
        portinfo = self.mas_scan()
        result = {}
        for key,vaule in portinfo.items():
            ipres = {}
            for k1,v1 in vaule.items():
                portinfo = []
                if v1.has_key('tcp'):
                    portinfo.extend(v1["tcp"].keys())
                if v1.has_key('udp'):
                    portinfo.extend(v1["udp"].keys())
                ipres[k1] = portinfo
            result[key] = ipres
        return result


class NmapScaninfo(object):
    def __init__(self,host='127.0.0.1',plist=[80,443], options='-P0 -T5 -sV --script=default --open'):
        self.host = host
        self.plist = plist
        self.options = options

    def int2str(self,myint):
        mystr = []
        for i in myint:
            mystr.append(str(i))
        return ','.join(mystr)
    def scan(self):
        result = {}
        try:
            nm = nmap.PortScanner()
            nr = nm.scan(hosts=self.host, ports=self.int2str(self.plist), arguments=self.options)#'-T5 -sV --script=default --open'
            
            if nr["scan"]:
                iwant = nr["scan"][self.host]
                youwant = {}    
                if iwant.has_key('tcp'):
                    youwant['procol'] = iwant["tcp"]
                if iwant.has_key('udp'):
                    youwant['procol'] = iwant["udp"]
                if iwant.has_key('tcp') and iwant.has_key('udp'):
                    iwant.update(youwant)

                result[self.host] = youwant['procol']
            else:
                for i in self.plist:
                    result[self.host] = {i:{}}
        except Exception, msg:
            print ("Error: port_scan: %s" % msg)
        return result



class NmapScanmas(object):
    def __init__(self,iplst, portlst,threads):
        self.iplst = iplst
        self.portlst = portlst
        self.threads = threads
        self.queuek = Queue.Queue()
        self.queuev = Queue.Queue()
        self.portres = []   

    def init_queue(self,masres):
        for key,value in masres.items():
            for k,v in value.items():
                self.queuek.put(k)
                self.queuev.put(v)
                
    def worker(self, *args, **kwargs):
        while True:
            try:    
                host = self.queuek.get_nowait()
                ports = self.queuev.get_nowait() 
            except:
                break    
            else:            

                nm = NmapScaninfo(host=host,plist=ports,options='-P0 -sV --open') #--script=default  -T5
                self.portres.append(nm.scan())  
        
                self.queuek.task_done()
                self.queuev.task_done()

        
    def start(self):
        mas = Get_Portinfo(destips = self.iplst, ports = self.portlst, rate=100)
        masres = mas.format()
        print json.dumps(masres,indent=4)
        self.init_queue(masres) 

        threads = []
        for i in xrange(self.threads):
            thread = threading.Thread(target=self.worker, args=(i,))
            threads.append(thread)
        for i in xrange(self.threads):
            threads[i].start()
        for i in xrange(self.threads):
            threads[i].join()
        print json.dumps(self.portres,indent=4)

if __name__ == "__main__":
    scan = NmapScanmas(iplst=['10.0.1.1-10.0.1.100'],portlst=['80','443','3389','8080','1080'],threads=5)
    scan.start()   