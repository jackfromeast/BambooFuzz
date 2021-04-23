# encoding: utf-8
from scapy.all import *
import threading
import sys
import psutil
import click
import signal

global stop_flag
stop_flag = False

def stop_handler(signum, frame):
    global stop_flag
    stop_flag = True

signal.signal(signal.SIGTERM, stop_handler)

#获取网卡名称和其ip地址，不包括回环
def get_netcard():
    netcard_info = []
    info = psutil.net_if_addrs()
    for k,v in info.items():
        for item in v:
            if item[0] == 2 and not item[1]=='127.0.0.1' and str(k)[0]=='t' and str(k)[1]=='a'and str(k)[2]=='p':
                netcard_info.append((k,item[1]))
    return netcard_info

def _stop(p):
    global stop_flag
    if stop_flag:
        return True
    else:
        return False

#开始监听网卡
def capture(network_card, pfilter, timeout=None):
    print("\033[1;36m[#] netcard info:")
    netcard_info=get_netcard()
    print(netcard_info)
    print ("[#] begin catching\033[0m")

    # iface是电脑网卡的名称 count是捕获报文的数目
    if timeout != None:
        dpkt = sniff(iface=network_card,filter=pfilter, timeout=int(timeout), stop_filter=_stop)
    else:
        dpkt = sniff(iface=network_card,filter=pfilter, stop_filter=_stop)

    if(dpkt==None):
        print("\033[1;36mThe netcard might wrong! Please select another one!\033[0m")
        return False

    print ("\033[1;36m[#] catch data successfully!\033[0m")
    return dpkt


def catch_pkt(network_card, pcap_file, filters, timeout, name):
    dpkt = capture(network_card, filters, timeout)
    wrpcap(pcap_file, dpkt)

    print("\033[1;36m[#] The sniffer[%s] stop listening. All his work done!\n\033[0m" % name)


@click.command()
@click.option('-filepath', default='./packets/tmp.pcap', help='Where you should save the captured packets.')
@click.option('-filters', default='host 192.168.0.1', help='Set packets filter.')
@click.option('-netcard', default='tap2_0', help='Set listening network cards.')
@click.option('-timeout', default=None, help='Set timeout.')
@click.option('-name', default='Default', help='Set sniffer name.')
def sniffer_main(filepath, filters, netcard, timeout, name):
    print("\033[1;36m\n[#] The scapy sniffer[%s] start listening.\033[0m" % name)
    catch_pkt(netcard, filepath, filters, timeout, name)


if __name__ =='__main__':
    sniffer_main()