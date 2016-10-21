#import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import StringIO
import gzip

def parsePCAP(pkts):
  ipdict = {}
  for pkt in pkts:
    #print "Source IP: " + pkt[IP].src	
    #print "Destination IP: " + pkt[IP].dst	
    #print "Source port: " + str(pkt[TCP].sport)	
    #print "Destinations port: " + str(pkt[TCP].dport)	
    #print "Packet Payload: " + str(pkt[TCP].payload)
    ip = pkt[IP].src
    if not ipdict.has_key(ip):
      ipdict[ip] = 1
    ipdict[ip] += 1

  print "IP Dictionary: "
  for ip in ipdict.keys():
    if ipdict[ip] > 500:
      print ip + " : " + str(ipdict[ip])
    #print ip.rjust(1), " : ".rjust(2), str(ipdict[ip]).rjust(3)

  ipfile = open("coffeeshop.txt", 'w')
  for ip in ipdict.keys():
    if ipdict[ip] > 500:
      ipfile.write(ip)
      ipfile.write("\n")
  ipfile.close()
  separateUsers(pkts, "coffeeshop.txt")

def separateUsers(pkts, ipfile):
  ipfile = open(ipfile, 'r')
  ips = []
  for line in ipfile:
    ips.append(line[:-1])
  
  if not os.path.exists("separated"):
    os.makedirs("separated")
  os.chdir("separated")
  for pkt in pkts:
    if pkt[IP].src in ips:
      pktfile = open(pkt[IP].src, 'a')
      pktfile.write("SrcIP: " + pkt[IP].src + "\n")
      pktfile.write("DstIP: " + pkt[IP].dst + "\n")
      pktfile.write("SrcPort: " + str(pkt[TCP].sport) + "\n")
      pktfile.write("DstPort: " + str(pkt[TCP].dport) + "\n")
      payload = str(pkt[TCP].payload)
      if "Content-Encoding: gzip" in payload:
        #print payload
        #raw_input("ay")
        payload = decodePayload(payload)      
      pktfile.write("PktPayload: " + payload + "\n\n" )
      pktfile.close()


  os.chdir("..")

def searchPkts(ipfileloc, keyword):
  ipdict = {}
  for ipfile in os.listdir(ipfileloc):   
    data = open(ipfile, 'r')
    for line in data:
      keywordloc = line.find(keyword)
      if keywordloc > -1:
        print data.name
        break

def decodeGzip(ip, ipfileloc):
  os.chdir(ipfileloc)
  if ip not in os.listdir(os.getcwd()):
    print "ip file not found"
  else:
    ipfile = open(ip, 'r')
    payloadRead = True
    for line in ipfile:
      if "PktPayload: " in line:
        payloadStream = StringIO.StringIO()
        payloadStream.write(line[12:])
      elif payloadRead:
        if "Host:" in line:
          payloadRead = False
        else:
          payloadStream.write(line)

    # unzip at this indent
    ##


def decodePayload(payload):
  fileStream = StringIO.StringIO(payload)
  gzipper = gzip.GzipFile(fileobj=fileStream)
  data = gzipper.read()
  return data

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print "usage: python lab3.py [pcap]"
    sys.exit()	
  pcap = rdpcap(sys.argv[1])
  pcap = [pkt for pkt in pcap if TCP in pkt]
  parsePCAP(pcap) 

  searchContinue = True
  os.chdir("separated")
  print os.getcwd()
  while searchContinue:
    keyword = raw_input("Keyword to search: ")
    if keyword == 'f':
      searchContinue = False
    else:
      searchPkts(os.getcwd(), keyword)