import sys
sys.path.append("..")
from boofuzz import *
from utils import *
from MsgTree import MsgTree
import warnings


# def print_node(etree, index=-1):
#     """ Traverse xml for boofuzz output """
#     index = index + 1 
#     s_static(value = (index * "\t" + f"<{etree.tag}>" + "\n"))
#     if etree.getchildren():
#         children = etree.getchildren()
#         for child in children:
#             print_node(child, index)
#     else:
#         s_static(value = (index+1) *"\t")
#         s_string( value = str(etree.text))
#     s_static(value = (index * "\t" + f"</{etree.tag}>" + "\n") )

def traverse_soap(etree, index=-1):
    """ Traverse soap for boofuzz output """
    index = index + 1 
    etree_tag = re.search('({[\s\S]*})([\s\S]*)', etree.tag).group(2)
    if "Body" in etree.tag:
        s_static(value = (f"<soap:Body>"))
    else:
        s_static(value = (f"<{etree_tag}>"))
    if etree.getchildren():
        children = etree.getchildren()
        for child in children:
            traverse_soap(child, index)
    else:
        s_string( value = str(etree.text))
    if "Body" in etree.tag:
        s_static(value = (f"</soap:Body>"))
    else:
        s_static(value = (f"</{etree_tag}>") )


def traverse_xml(etree, index=-1):
    """ Traverse xml for boofuzz output """
    index = index + 1 
    s_static(value = ((index-1) * "\t" + f"<{etree.tag}>" + "\n"))
    if etree.getchildren():
        children = etree.getchildren()
        for child in children:
            traverse_xml(child, index)
    else:
        s_static(value = (index+1) *"\t")
        s_string(value = str(etree.text))
    s_static(value = ( (index-1) * "\t" + f"</{etree.tag}>" + "\n") )

# fuzz get method
def fuzz_get_static(msgtree, request_index, session):
    """Fuzz for GET requests
        request_index: index the block 
    """
    not_fuzz_list = ["Method", "Path", "version", "optContent"]
    s_initialize(name=f"Request-{request_index}")
    with s_block("Request-Line"):
        # Line-1 Method
        paths = msgtree.children("Path")
        headers = msgtree.children("Headers")
        params = msgtree.children("parameters")
        s_group("Method", ["GET"])
        s_delim(name="space-1", value=" ", fuzzable=False)
        

        # Line-1 Path
        s_static("/", name="Request-URI")
        for index, path in enumerate(paths):
            index = str(index)
            s_static(name="path"+index, value=path.data)
            if int(index) < (len(paths)-1):
                s_static(name="path_delim-" + index, value="/" )
        
        # Line-1 param
        s_static(name = "param-start", value="?")
        # Traverse the param tree and generate the parameter part
        for index, param in enumerate(params):
            index = str(index)
            s_static(name="key-"+index, value=param.identifier)
            s_static(name="equal_sign-" + index, value="=")
            s_string(name="value-"+index, value=param.data)
            # Add a & (delim) after non-last parameter 
            if int(index) < len(params)-1:
                s_static(name="param_delim-"+index, value="&")
        s_delim(name="space-2", value=" ", fuzzable=False)

        # Line-1 version 
        s_static(name="Version", value=msgtree.get_node("version").data)
        s_static(name="Line-CRLF", value="\r\n")

        # Line-n Headers
        # Traverse the param tree and generate the parameter part
        for index, header in enumerate(headers):
            if header.tag == "Content-Length":
                s_static(name=f"header-key-{index}", value=header.tag)
                s_static(name=f"delim--{index}", value=": ")
                s_size(block_name="Payload",fuzzable=False, output_format="ascii")
            else:
                s_static(name=f"header-key-{index}", value=header.tag)
                s_static(name=f"delim--{index}", value=": ")
                if header.data[-2:] == '\r\n':
                    header.data = header.data[:-2]
                s_string(name=f"header-value-{index}", value=header.data)
            s_static(name=f"line_delim--{index}", value="\r\n" )
        s_static(name="Request-Line-CRLF", value="\r\n")

    session.connect(s_get(f"Request-{request_index}"))

# fuzz post method
def fuzz_post_static(msgtree, etree, request_index, session):
    """Fuzz for POST requests
        request_index: index the block 
    """
    not_fuzz_list = ["Method", "Path", "version"]
    s_initialize(name=f"Request-{request_index}")
    with s_block("Request-Line"):
        # Line-1 Method
        paths = msgtree.children("Path")
        headers = msgtree.children("Headers")
        s_group("Method", ["POST"])
        s_delim(name="space-1", value=" ", fuzzable=False)

        # Line-1 Path
        s_static("/", name="Request-URI")
        for index, path in enumerate(paths):
            index = str(index)
            s_static(name="path"+index, value=path.data)
            if int(index) < (len(paths)-1):
                s_static(name="path_delim-" + index, value="/" )
        s_delim(name="space-2", value=" ", fuzzable=False)

        # Line-1 version 
        s_static(name="Version", value=msgtree.get_node("version").data)
        s_static(name="Line-CRLF", value="\r\n")

        # Line-n Headers
        for index, header in enumerate(headers):
            if header.tag == "Content-Length":
                s_static(name=f"header-key-{index}", value=header.tag)
                s_static(name=f"delim--{index}", value=": ")
                s_size(block_name="Payload",fuzzable=False, output_format="ascii")
            else:
                s_static(name=f"header-key-{index}", value=header.tag)
                s_static(name=f"delim--{index}", value=": ")
                if header.data[-2:] == '\r\n':
                    header.data = header.data[:-2]
                s_static(name=f"header-value-{index}", value=header.data)
            s_static(name=f"line_delim--{index}", value="\r\n" )
        s_static(name="Request-Line-CRLF", value="\r\n")

    with s_block("Payload"):
        # payload
        # case 1: xml
        if etree != None:
            # msgtree
            node = msgtree.get_node("xml-info")

            s_static(name="xml-info", value=node.data)
            
            # etree
            if "soap" not in etree.tag:
                s_static(value="\n")
            # case 1:xml
                traverse_xml(etree)
            # case 2:soap
            else:
                body = etree.getchildren()    
                s_static('<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">')
                traverse_soap(body[0])
                s_static("</soap:Envelope>")
            
        else:
            s_static(value="\n")
            node_list = msgtree.leaves("data")
            for node in node_list:
                s_static(name = node.tag, value=node.tag)
                s_static(value = "=")
                s_static(name = node.data, value=node.data)
            s_static(name = "CRLF",value="\r\n")
    session.connect(s_get(f"Request-{request_index}"))



if __name__ == "__main__":
    file_path = "pcap/Dlink-DIR823G.pcap"
    trees_list = MsgTree.build_tree_list(file_path)
    target_ip = "192.168.111.128"
    target_port = 80
    session = Session(
        target=Target(connection=TCPSocketConnection(target_ip, target_port)),
    )
    print(trees_list)
    for index, couple in enumerate(trees_list):
        if couple[0].get_node("Method").data == b"GET":
            fuzz_get_static(msgtree=couple[0]  ,session = session, request_index=index)
        else:
            fuzz_post_static(msgtree=couple[0], etree=couple[1], session=session, request_index=index)
    # fuzz_get_static(msgtree=trees_list[0][0], session = session, request_index=1 )
    # fuzz_get_static(msgtree , request_index=1, session=session)
    # session.feature_check()

    session.fuzz()
