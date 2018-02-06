#!/usr/bin/env python

from scapy.all import *
#python3 pip py3-scapy
#python
# from scapy.layers import dot11 as Dot11
import scapy.layers.dot11
ap_list=[]
ap_dict={}
user_list=[]
jl=[]


class drivers_m():
    def __init__(self,mac,rate,antsignal):
        self.MAC=mac#mac  ap=addr2  c=addr1
        self.RATE=rate#gonglv  rate
        self.ANTSIGNAL=antsignal#xinhao dbm dbm_antsignal
        self.CHANNEL=""#pinglv channel_freq
        self.INFO=""#ssid
        self.AP=""# t  f
        self.BSSID=""#ssid info link
        self.ANTENNA=""#tianxian antenna

    def getall(self):
        s=[self.MAC, self.ANTSIGNAL,self.CHANNEL,self.RATE,self.ANTENNA,self.AP,self.BSSID,self.INFO]
        return s

    def mac(self):
        return self.MAC
    def rate(self):
        return self.RATE
    def antsignal(self):
        return self.ANTSIGNAL
    def channel(self):
        return self.CHANNEL
    def info(self):
        return self.INFO
    def ap(self):
        return self.AP
    def antenna(self):
        return self.ANTENNA
    def bssid(self):
        return self.BSSID


a=[]
s=[]
def PacketHandler(pkt):

    global a
    if pkt.haslayer(scapy.layers.dot11.Dot11):
        if pkt.type == 1 and pkt.subtype == 9:
            if pkt.addr1 not in a:
                a.append(pkt.addr1)
                x = drivers_m(pkt.addr1, pkt.rate, pkt.dbm_antsignal)
                x.AP=False
                x.CHANNEL=pkt.channel_freq
                x.ANTENNA=pkt.antenna
                x.BSSID=pkt.addr2
                s.append(x)
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in a:
                a.append(pkt.addr2)
                x=drivers_m(pkt.addr2,pkt.rate,pkt.dbm_antsignal)
                x.AP=True
                x.CHANNEL=pkt.channel_freq
                x.ANTENNA=pkt.antenna
                x.BSSID=pkt.addr2
                x.INFO=pkt.info
                s.append(x)

if __name__=='__main__':
    import time
    import os

    # os.system("airmon-ng start wlp2s0")
    # snf(1)
    sniff(filter="", iface="mon0", prn=PacketHandler, count=8000)

    for i in s:
        print(i.getall())