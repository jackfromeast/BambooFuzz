from scapy.all import *
import scapy_http.http as http
import requests
import json
from urllib import parse

# header文本转成字典
# def get_headers(header_raw):
#     return dict(line.split(": ", 1) for line in header_raw.split("\n") if line != '')
 
def get_headers(file_path):
    ''' 
    Get the headers of the http packet 
    (the data type is bytes)
    '''
    
    pkts = rdpcap(file_path)
    req_headers = []
    for pkt in pkts:
        if 'TCP' in pkt and pkt['TCP'].fields['dport']==80 and pkt.haslayer("HTTPRequest"):
            if packet_filter(pkt):
                req_header = pkt["HTTPRequest"].fields
                del req_header["Headers"]
                req_headers.append(req_header)
    return req_headers


def get_payloads(file_path):
    ''' Get the payloads of the http packet 
    (the data type is bytes)
    '''
    pkts = rdpcap(file_path)
    req_payloads = []
    for pkt in pkts:
        if 'TCP' in pkt and pkt['TCP'].fields['dport']==80 and pkt.haslayer("HTTPRequest"):
            # filter 
            if packet_filter(pkt) :
                if pkt["HTTPRequest"].fields["Method"] == b"POST":
                    req_header = pkt["HTTPRequest"].fields
                    identifier = pkt["IP"].id
                    ack = pkt["TCP"].ack
                    # splicing post data
                    payload = bytes(pkt["HTTPRequest"].payload).decode()
                    for pkt in pkts:
                        if pkt.haslayer("TCP"):
                            if pkt["TCP"].ack == ack and identifier<int(pkt["IP"].id):
                                payload = payload + bytes(pkt["Raw"].load).decode()
                        payload.replace("\\\\", "\\")
                    req_payloads.append(payload)
                else:
                    req_payloads.append("0")
    return req_payloads


def get_headers_tree_from_packet(file_path):
    ''' Get the header of the generated msgtree '''
    Headers = get_headers(file_path)
    del Headers["Path"]
    del Headers["Method"]
    del Headers["Http-Version"]
    return Headers


def get_headers_tree(header_dic):
    ''' Get the header '''
    Headers = header_dic
    del Headers["Path"]
    del Headers["Method"]
    del Headers["Http-Version"]
    return Headers


def get_url_from_packet(file_path):
    ''' splicing URL from packet '''
    header = get_headers(file_path)
    url = header["Host"] + header["Path"]
    return url

def get_url(header_dic):
    url = header_dic["Host"] + header_dic["Path"]
    return url


def get_params(url):
    ''' Get param-key and param-value in url return a list '''
    params = parse.parse_qs(parse.urlparse(url).query)
    for key, value in params.items():
        value = [x.decode() for x in value]
        params[key] = "".join(value)
        params[key] = params[key].encode()
    return params

def method_is_get(method):
    ''' Whether the submission method is get '''
    if method == b"GET":
        return 1
    else:
        return 0


def is_fuzzelement(key):
    " # Whether key is fuzz element "
    not_fuzzable_element = ["Host", "User-Agent", "Accept", "Accept-Language",
     "Accept-Encoding", "X-Request-With", "X-Prototype-Version", "Connection", "Referer", "Cookie"]
    if key in not_fuzzable_element:
        return 0
    else:
        return 1

def path_split(path):
    ''' Split the url '''
    path = str(path)
    result = path.split("/")
    result = result[1:]
    return result

# filter
def packet_filter(packet):
    '''Filter static resources'''
    filter_list = ["img", "gif", "png", "xml", "ico", "bmp", "jpg", "css", ".js", "tml"]
    path = str(packet["HTTPRequest"].fields["Path"])

    # Whether to fuzz static resources with parameters
    if "?" in path:
        true_path = re.search(r"[\s\S]*\?", path).group()
        true_path = true_path[:-1]
    # the last three characters in path
    else:
        true_path = path

    if path[-4:-1] in filter_list:
        return 0
    else:
        return 1

def str_to_dic(string):
    """ convert string in post to dic
    used to split payload data into dic
    """
    pairs = string.split(",")
    dic = {}
    for pair in pairs:
        pair = pair.split("=")
        dic[pair[0]] = pair[1]
    return dic


def rm_bracket(string):
    "Remove the braces during soap processing"
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