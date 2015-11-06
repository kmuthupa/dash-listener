from scapy.all import *
import requests 
def record_tally():
  data = {
    "date": time.strftime("%Y-%m-%d"), 
    "tally": '1'
  }
  requests.post("https://sheetsu.com/apis/390c6259", data)

def arp_display(pkt):
  if pkt[ARP].op == 1: 
    if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      print "ARP Probe from: " + pkt[ARP].hwsrc
      if pkt[ARP].hwsrc == '74:c2:46:c3:e3:49': 
        print "Pushed Tide..."
        record_tally()
      else:
        print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print sniff(prn=arp_display, filter="arp", store=0, count=10)
