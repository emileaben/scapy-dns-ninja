#!/usr/bin/env python
### adapted from : http://thepacketgeek.com/scapy-p-09-scapy-and-dns/
from scapy.all import *
import sys
from random import shuffle
import re
import yaml
import traceback
import os.path

def read_conffile( filename ):
   conf = {}
   try:
      with open(filename,'r') as fh:
         conf = yaml.load( fh )
   except:
      print "Error reading config file: %s" % ( filename )
   return conf

conf = read_conffile('ninja-server.conf')
lists = {}

def read_destfile( list_name, lists ):
    filename = "./%s/ips.txt" % ( list_name )
    dests = []
    with open(filename,'r') as fh:
        for line in fh:
            line = line.rstrip('\n')
            dests.append( line ) 
    shuffle( dests )
    lists[ list_name ] = { 
        'dests': dests,
        'mtime': os.path.getmtime( filename ),
        'length': len(dests),
        'dest_idx': 0
    }
    print >>sys.stderr, "list %s successfully loaded" % ( list_name )
    return lists

## read the default list
read_destfile('_default',lists)

def generate_A_response( pkt, dest_ip ):
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
      )
   return resp

def DNS_Responder(conf,lists):
    #TODO better regex
    re_getlist = re.compile(r'([a-z0-9\-]+)\.%s\.$' % ( conf['ServerDomain'] ) )
    def getResponse(pkt):
        print "RECEIVED: %s" % ( pkt.summary() )
        global dest_idx
        if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[IP].src != conf['ServerIP']):
            try:
               if ( pkt[DNS].qd.qtype in [1,28] ): ###  A or AAAA
                  # sensible default
                  list_name = '_default'
                  list_match = re.search( re_getlist, pkt[DNS].qd.qname.lower() )
                  if list_match and os.path.exists( "./%s/ips.txt" % ( list_match.group(1) ) ):
                      list_name = list_match.group(1)
                      if list_name not in lists or os.path.getmtime("./%s/ips.txt" % (list_name) ) > lists[list_name]['mtime']:
                         ## read if the list wasn't read yet or if the mtime changed
                         read_destfile( list_name, lists )
                  try:
                      dest_idx = lists[list_name]['dest_idx']
                      dest_ip = lists[list_name]['dests'][dest_idx]
                      if lists[list_name]['dest_idx'] < lists[list_name]['length']-1:
                          lists[list_name]['dest_idx'] += 1
                      else:
                          print "list reset %s" % ( list_name )
                          #TODO shuffle? configurable?
                          shuffle( lists[list_name]['dests'] )
                          lists[list_name]['dest_idx'] = 0 ## reset to beginning
                      resp = generate_A_response( pkt, dest_ip )
                      send(resp,verbose=0)
                      return "sent resp for %s" % ( dest_ip )
                  except:
                       print "error on packet: %s" % ( pkt.summary() )
                       print sys.exc_info()
               else:
                  print "query type not supported"
            except:
                print "%s" % ( traceback.print_tb( sys.exc_info()[2] ) )
        else: 
            print "no qd.qtype in this dns request?!"
    return getResponse

filter = "udp port 53 and ip dst %s and not ip src %s" % (conf['ServerIP'], conf['ServerIP'])
sniff(filter=filter,store=0,prn=DNS_Responder(conf,lists))
