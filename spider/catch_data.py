# encoding: utf-8
from scapy.all import *
import threading
import sys
import psutil



file_path="/home/summer/Documents/demo.pcap"
output_path="/home/summer/Documents/output.txt"
my_filter1="ip.src == 192.168.0.1" #只捕获源地址是192.168.0.1的包
my_filter2="ip.dst == 192.168.0.1" #只捕获目标地址是192.168.0.1的包
my_filter3="ip.addr == 192.168.0.100" #捕获源地址或目标地址是192.168.0.100的包

#获取网卡名称和其ip地址，不包括回环
def get_netcard():
    netcard_info = []
    info = psutil.net_if_addrs()
    for k,v in info.items():
        for item in v:
            if item[0] == 2 and not item[1]=='127.0.0.1' and str(k)[0]=='t' and str(k)[1]=='a'and str(k)[2]=='p':
                netcard_info.append((k,item[1]))
                print()
    return netcard_info

#开始监听网卡
def capture(select_id=0,my_filter=my_filter3):
    print("get netcard info:")
    netcard_info=get_netcard()
    print ("begin catch:")
    # 下面的iface是电脑网卡的名称 count是捕获报文的数目
    #如果5s内没捕捉到包说明网卡可能绑错了，需要重新点击
    #select_id选择可以监听的网卡id,默认是第1个
    #filter can set filter rules
    dpkt = sniff(iface=str(netcard_info[select_id][0]),filter=None,timeout=5)  
    #dpkt = sniff(iface=str(netcard_info[select_id][0]),filter=None,count=5)
    print(netcard_info[select_id][0])
    if(dpkt==None):
        print("The netcard is wrong!Please select another one!")
        return False
    print ("catch data successfully!")
    return dpkt

#这个函数用来解析报文
def dealwith(dpkt):
    wrpcap(file_path, dpkt)
    print ("data saved in "+file_path)
 
    pcks = rdpcap(file_path)
    print ("begin to parse pcap:")
 
    # 输出重定向  将在控制台的输出重定向到 txt文本文件中
    output = sys.stdout
    outputfile = open(output_path, 'w')
    sys.stdout = outputfile
 
    zArp = 0
    zIcmp = 0
    ipNum = set()
 
    for p in pcks:
        status1 = p.payload.name  # 可能是ARP的报文
        status2 = p.payload.payload.name  # 可能是TCP报文 也可能是ICMP的报文
 
        # p.show() 输出报文， 在符合的情况下
        if status1 == 'IP':
            ipNum.add(p.payload.src)  # 将ip报文的源地址，和目的地址存在set集合里面（set去重）
            ipNum.add(p.payload.dst)
            p.show()
            print (" ")
        else:
            if status1 == 'ARP':
                p.show()
                print(" ")
                zArp += 1
 
            if status2 == 'ICMP':
                p.show()
                print(" ")
                zIcmp += 1
 
    print ('IP：' + str(len(ipNum)) + ' ARP：' + str(zArp) + ' ICMP：' + str(zIcmp)) # 报文数量的输出
 
    outputfile.close()
    sys.stdout = output  # 恢复到控制台输出
 
    print ("输出结束")
    print (dpkt)



if __name__ == '__main__':
    print (get_netcard())
    dpkt=capture()
    times=1
    while(times):
        if(dpkt!=False):
            dealwith(dpkt) # 运行报文捕获函数
        else:
            dpkt=capture()
        times=times-1
 
