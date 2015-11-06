import socket
import struct
import binascii
import time
import json
import urllib2
import requests

macs = {
    '74c246c3e349' : 'dash_tide'
}

def post_data():
    data = {
      "date": time.strftime("%Y-%m-%d"),
      "tally": '1'
    }
    requests.post("https://sheetsu.com/apis/390c6259", data)   

def record_tally():
    print 'triggering tally... '
    post_data();

rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

while True:
    packet = rawSocket.recvfrom(2048)
    ethernet_header = packet[0][0:14]
    ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
    arp_header = packet[0][14:42]
    arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
    # skip non-ARP packets
    ethertype = ethernet_detailed[2]
    if ethertype != '\x08\x06':
        continue
    source_mac = binascii.hexlify(arp_detailed[5])
    source_ip = socket.inet_ntoa(arp_detailed[6])
    dest_ip = socket.inet_ntoa(arp_detailed[8])
    if source_mac in macs:
        #print "ARP from " + macs[source_mac] + " with IP " + source_ip
        if macs[source_mac] == 'dash_tide':
            record_tally()
    else:
        print "Unknown MAC " + source_mac + " from IP " + source_ip
