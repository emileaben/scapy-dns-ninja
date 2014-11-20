#!/usr/bin/env python
### adapted from : http://thepacketgeek.com/scapy-p-09-scapy-and-dns/
from scapy.all import *
import sys
from random import shuffle
import yaml

def read_conffile( filename ):
   conf = {}
   try:
      with open(filename,'r') as fh:
         conf = yaml.load( fh )
   except:
      print "Error reading config file: %s" % ( filename )
   return conf

conf = read_conffile('ninja-server.conf')

class DNSSOARecord(Packet):
   # http://tools.ietf.org/html/rfc1035#section-3.3.13
   name = "DNSSOA"
   fields_desc = [ 
      DNSStrField("mname", None),
      DNSStrField("rname", None),
      IntField("serial", 1),
      IntField("refresh", 3600), 
      IntField("retry", 600),
      IntField("expire", 864000),
      IntField("minimum", 300)
   ]
   def h2i(self, pkt, x):
      return str(x)
   def i2m(self, pkt, x):
      return str(x)

def read_destfile( filename ):
    dests = []
    with open(filename,'r') as fh:
        for line in fh:
            line = line.rstrip('\n')
            dests.append( line ) 
    shuffle( dests )
    return dests

dest_idx = 0
dests = read_destfile('ips.txt')
dests_len = len( dests )


def DNS_Responder(localIP):
    def getResponse(pkt):
        print "RECEIVED: %s" % ( pkt.summary() )
        global dest_idx
        if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[IP].src != localIP):
            print pkt[DNS].qd
            if ( pkt[DNS].qd.qtype == 1 ): ###  1 = 'A'
                    try:
                        dest_ip = dests[dest_idx]
                        resp = IP(dst=pkt[IP].src, id=pkt[IP].id)\
                            /UDP(dport=pkt[UDP].sport, sport=53)\
                            /DNS( id=pkt[DNS].id,
                                  aa=1, #we are authoritative
                                  qr=1, #it's a response
                                  rd=pkt[DNS].rd, # copy recursion-desired
                                  qdcount=pkt[DNS].qdcount, # copy question-count
                                  qd=pkt[DNS].qd, # copy question itself
                                  ancount=1, #we provide a single answer
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=1 ,rdata=dest_ip ),
                                  nscount=1, #we provide a single auth record
                                  ns=DNSRR(rrname=conf['ServerDomain'], ttl=86400, type='NS', rdata=conf['ServerName'] )
                            )
                            #/DNSRR(rrname="random-ipv4.ox.sg.ripe.net",rdata=dest_ip))
                        send(resp,verbose=0)
                        dest_idx += 1
                        if dest_idx >= dests_len: dest_idx = 0
                        return "sent resp for %s" % ( dest_ip )
                    except:
                        print "error on packet: %s" % ( pkt.summary() )
                        print sys.exc_info()
            elif ( pkt[DNS].qd.qtype == 2 ): ###  2 = 'NS'
                # regardless of the question we only know one answer
                print "we got an NS request, exiting!"
                resp = IP(dst=pkt[IP].src, id=pkt[IP].id)\
                       /UDP(dport=pkt[UDP].sport, sport=53)\
                       /DNS( id=pkt[DNS].id,
                                  aa=1, #we are authoritative
                                  qr=1, #it's a response
                                  rd=pkt[DNS].rd, # copy recursion-desired
                                  qdcount=pkt[DNS].qdcount, # copy question-count
                                  qd=pkt[DNS].qd, # copy question itself
                                  ancount=1, #we provide a single answer
                                  an=DNSRR(rrname=conf['ServerDomain'], ttl=86400, type='NS', rdata=conf['ServerName'] )
                       )
                send(resp,verbose=0)
            elif ( pkt[DNS].qd.qtype == 6 ): ###  6 = 'SOA'
                print "we got a SOA request, exiting!"
                soa = DNSSOARecord( mname=conf['ServerName'], rname="root.%s" % ( conf['ServerName'] ) ) 
                resp = IP(dst=pkt[IP].src, id=pkt[IP].id)\
                       /UDP(dport=pkt[UDP].sport, sport=53)\
                       /DNS( id=pkt[DNS].id,
                                  aa=1, #we are authoritative
                                  qr=1, #it's a response
                                  rd=pkt[DNS].rd, # copy recursion-desired
                                  qdcount=pkt[DNS].qdcount, # copy question-count
                                  qd=pkt[DNS].qd, # copy question itself
                                  ancount=1, #we provide a single answer
                                  an=DNSRR(
                                       rrname=conf['ServerDomain'],
                                       ttl=86400,
                                       type=6,
                                       rdata=str(soa)
                                  )
                       )
                send(resp,verbose=0)
            else:
                print "we got a not A/NS/SOA request, exiting!"
        else:
            return pkt.summary()
    return getResponse

filter = "udp port 53 and ip dst %s and not ip src %s" % (conf['ServerIP'], conf['ServerIP'])
sniff(filter=filter,prn=DNS_Responder(conf['ServerIP']))
