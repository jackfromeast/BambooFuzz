from scapy.all import *
import scapy_http.http as http
import requests
import json
from urllib import parse

def get_headers(file_path):
    ''' 
    从捕获packet中获取Header信息, 
    返回 list.
    '''
    pkts = rdpcap(file_path)
    req_headers = []
    for pkt in pkts:
        # HTTP请求数据包
        if 'TCP' in pkt and pkt['TCP'].fields['dport']==80 and pkt.haslayer("HTTPRequest"):
            # 过滤静态资源请求
            if packet_filter(pkt):
                req_header = pkt["HTTPRequest"].fields
                del req_header["Headers"]
                req_headers.append(req_header)
    return req_headers


def get_payloads(file_path):
    ''' 
    从捕获packet中获取payload信息, 
    返回 list.
    '''
    pkts = rdpcap(file_path)
    req_payloads = []
    for pkt in pkts:
        if 'TCP' in pkt and pkt['TCP'].fields['dport']==80 and pkt.haslayer("HTTPRequest"):
            # 过滤静态资源请求
            if packet_filter(pkt) :
                if pkt["HTTPRequest"].fields["Method"] == b"POST":
                    req_header = pkt["HTTPRequest"].fields
                    # 存在数据包过长情况, 根据ID和ACK进行数据拼接
                    identifier = pkt["IP"].id
                    ack = pkt["TCP"].ack
                    # 拼接POST数据
                    payload = bytes(pkt["HTTPRequest"].payload).decode()
                    for pkt in pkts:
                        if pkt.haslayer("TCP"):
                            # ACK相同且ID在一定范围内的数据包进行拼接
                            if pkt["TCP"].ack == ack and identifier<int(pkt["IP"].id):
                                payload = payload + bytes(pkt["Raw"].load).decode()
                        payload.replace("\\\\", "\\")
                    req_payloads.append(payload)
                else:
                    req_payloads.append("0")
    return req_payloads


def get_headers4tree_from_packet(file_path):
    ''' 
    从数据包获取header部分，方便树的生成, 删除Path, Method, Http-Version部分.
    返回 dic
    '''
    Headers = get_headers(file_path)
    del Headers["Path"]
    del Headers["Method"]
    del Headers["Http-Version"]
    return Headers


def get_headers4tree(header_dic):
    ''' 
    从dic获取header部分，方便树的生成, 删除Path, Method, Http-Version部分. 
    返回 dic.
    '''
    Headers = header_dic
    del Headers["Path"]
    del Headers["Method"]
    del Headers["Http-Version"]
    return Headers


def get_url_from_packet(file_path):
    '''
    从packet拼接URL. 
    返回 string.
    '''
    header = get_headers(file_path)
    url = header["Host"] + header["Path"]
    return url

def get_url(header_dic):
    """
    从dic拼接URL. 
    返回 string.
    """
    url = header_dic["Host"] + header_dic["Path"]
    return url


def get_params(url):
    ''' 
    获取参数key和value. 
    返回 dic.
    '''
    params = parse.parse_qs(parse.urlparse(url).query)
    for key, value in params.items():
        value = [x.decode() for x in value]
        params[key] = "".join(value)
        params[key] = params[key].encode()
    return params

def method_is_get(method):
    ''' 
    判断请求类型是否为GET. 
    返回 0 or 1.
    '''
    if method == b"GET":
        return 1
    else:
        return 0


def is_fuzzelement(key):
    """ 判断是否为要fuzz字段,
    例如 [Host, Accept, ...].  
    返回 0 or 1.    
    """
    not_fuzzable_element = ["Host", "User-Agent", "Accept", "Accept-Language",
     "Accept-Encoding", "X-Request-With", "X-Prototype-Version", "Connection", "Referer", "Cookie"]
    if key in not_fuzzable_element:
        return 0
    else:
        return 1

def path_split(path):
    ''' 
    分割Path. 
    返回 list. 
    '''
    # 根据'/'分割
    path = str(path)
    result = path.split("/")
    result = result[1:]
    return result

def packet_filter(packet):
    '''
    过滤静态资源, 例如img, gif, ...
    返回 0 or 1. 
    '''
    filter_list = ["img", "gif", "png", "xml", "ico", "bmp", "jpg", "css", ".js", "tml"]
    path = str(packet["HTTPRequest"].fields["Path"])

    # 判断请求是否包含参数(通过是否含有问号判断)
    if "?" in path:
        true_path = re.search(r"[\s\S]*\?", path).group()
        true_path = true_path[:-1]
    else:
        true_path = path

    # 判断最后三个字符是否为过滤内容
    if path[-4:-1] in filter_list:
        return 0
    else:
        return 1

def str_to_dic(string):
    """ 
    转换payload中data为字典存储. 
    返回 dic
    """
    pairs = string.split("&")
    dic = {}
    for pair in pairs:
        pair = pair.split("=")
        dic[pair[0]] = pair[1]
    return dic


def rm_bracket(string):
    """ 
    去除soap标签的大括号内容,
    例如: 解析时标签为'{xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"}Body', 
    在生成报文时只需'Body', 因此删除.
    返回 string.
    """
    group = re.search('({[\s\S]*})([\s\S]*)', string)
    return group.group(2)


# def preorder_traverse(etree):
#     print(etree.tag)
#     if etree.text:
#         print(etree.text)
#     if etree.getchildren():
#         children = etree.getchildren()
#         for child in children:
#             preorder_traverse(child)
#     else:
#         return

# header文本转成字典
# def get_headers(header_raw):
#     return dict(line.split(": ", 1) for line in header_raw.split("\n") if line != '')
 