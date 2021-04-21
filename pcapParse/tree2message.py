import sys
from boofuzz import *
from .utils import *
from .MsgTree import MsgTree
import warnings


class Serializer(object):
    """
    序列化生成 boofuzz 报文
    """
    def traverse_soap(self, etree, index=-1):
        """ 
        遍历soap协议报文, 生成对应boofuzz内容.
        """
        index = index + 1 
        # 取非{}内容
        etree_tag = re.search('({[\s\S]*})([\s\S]*)', etree.tag).group(2)
        # 如果为Body,输入固定字符;否则输出开始标签
        if "Body" in etree.tag:
            s_static(value = (f"<soap:Body>"))
        else:
            s_static(value = (f"<{etree_tag}>"))
        
        # 判断是否有子结点
        if etree.getchildren():
            # 对子结点递归
            children = etree.getchildren()
            for child in children:
                traverse_soap(child, index)        
        # 否则输出最内层的值
        else:
            s_string( value = str(etree.text))
        
        # 如果为Body,输入固定字符;否则输出结束标签
        if "Body" in etree.tag:
            s_static(value = (f"</soap:Body>"))
        else:
            s_static(value = (f"</{etree_tag}>") )


    def traverse_xml(self, etree, index=-1):
        """ 
        遍历xml报文, 生成对应boofuzz内容. 
        """
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


    def fuzz_get_static(self, msgtree, request_index, session):
        """
        Fuzz GET请求
        """
        not_fuzz_list = ["Method", "Path", "version", "optContent"]

        # boofuzz初始化
        s_initialize(name=f"Request-{request_index}")
        with s_block("Request-Line"):
            # Line-1 Method 部分
            paths = msgtree.children("Path")
            headers = msgtree.children("Headers")
            params = msgtree.children("parameters")
            s_group("Method", ["GET"])
            s_delim(name="space-1", value=" ", fuzzable=False)
            

            # Line-1 Path 部分, 遍历生成 path 部分
            s_static("/", name="Request-URI")

            for index, path in enumerate(paths):
                index = str(index)
                s_static(name="path"+index, value=path.data)
                if int(index) < (len(paths)-1):
                    s_static(name="path_delim-" + index, value="/" )
            
            # Line-1 param 部分 以 '?' 开始, 遍历生成 param 部分
            s_static(name = "param-start", value="?")

            for index, param in enumerate(params):
                index = str(index)
                s_static(name="key-"+index, value=param.identifier)
                s_static(name="equal_sign-" + index, value="=")
                s_string(name="value-"+index, value=param.data)
                # 非最终键值对输出 '&' 作为连接符
                if int(index) < len(params)-1:
                    s_static(name="param_delim-"+index, value="&")
            s_delim(name="space-2", value=" ", fuzzable=False)

            # Line-1 version 部分
            s_static(name="Version", value=msgtree.get_node("version").data)
            s_static(name="Line-CRLF", value="\r\n")

            # Line-n Headers 部分, 遍历生成 header 部分
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

        if request_index == 'login':
            session.connect(s_get(f"Request-{request_index}"))
        else:
            session.connect(s_get(f'Request-login'), s_get(f'Request-{request_index}'))


    def fuzz_post_static(self, msgtree, etree, request_index, session):
        """
        Fuzz POST请求
        """
        not_fuzz_list = ["Method", "Path", "version"]
        
        # boofuzz初始化
        s_initialize(name=f"Request-{request_index}")
        
        # Request-Line block
        with s_block("Request-Line"):
            # Line-1 Method 部分
            paths = msgtree.children("Path")
            headers = msgtree.children("Headers")
            s_group("Method", ["POST"])
            s_delim(name="space-1", value=" ", fuzzable=False)

            # Line-1 Path 部分, 遍历生成 path 部分
            s_static("/", name="Request-URI")
            for index, path in enumerate(paths):
                index = str(index)
                s_static(name="path"+index, value=path.data)
                if int(index) < (len(paths)-1):
                    s_static(name="path_delim-" + index, value="/" )
            s_delim(name="space-2", value=" ", fuzzable=False)

            # Line-1 version 部分
            s_static(name="Version", value=msgtree.get_node("version").data)
            s_static(name="Line-CRLF", value="\r\n")

            # Line-n Headers 部分, 遍历生成 header 部分
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

        # Payload block
        with s_block("Payload"):
            # 判断 etree 是否为空: 空 data 生成, 非空 etree 遍历
            if etree != None:
                # 生成 msgtree xml-info 部分
                node = msgtree.get_node("xml-info")
                s_static(name="xml-info", value=node.data)
                
                # 判断etree内容: 非 soap 协议, 遍历生成 xml 报文, 否则生成 soap 报文
                if "soap" not in etree.tag:
                    s_static(value="\n")
                # case 1: xml
                    traverse_xml(etree)
                # case 2: soap
                else:
                    body = etree.getchildren()    
                    s_static('<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">')
                    traverse_soap(body[0])
                    s_static("</soap:Envelope>")
                
            else:
                s_static(value="\n")
                node_list = msgtree.leaves("data")
                # 遍历 msgtree 的 data 部分
                for node in node_list:
                    s_static(name = node.tag, value=node.tag)
                    s_static(value = "=")
                    s_static(name = node.data, value=node.data)
                s_static(name = "CRLF",value="\r\n")
        
        if request_index == 'login':
            session.connect(s_get(f"Request-{request_index}"))
        else:
            session.connect(s_get(f'Request-login'), s_get(f'Request-{request_index}'))


def fill_session(session, file_path_l, file_path_m):

    serializer = Serializer()

    login_tree = MsgTree.build_login_tree(file_path_l)

    if login_tree[0].get_node("Method").data == b"GET":
        serializer.fuzz_get_static(msgtree=login_tree[0], session=session, request_index='login')
    else:
        serializer.fuzz_post_static(msgtree=login_tree[0], etree=login_tree[1], session=session, request_index='login')


    trees_list = MsgTree.build_tree_list(file_path_m)

    for index, couple in enumerate(trees_list):
        if couple[0].get_node("Method").data == b"GET":
            serializer.fuzz_get_static(msgtree=couple[0]  ,session = session, request_index=index)
        else:
            serializer.fuzz_post_static(msgtree=couple[0], etree=couple[1], session=session, request_index=index)
    
    print(index)
    
    return session


if __name__ == "__main__":
    
    file_path = "pcap/Dlink-DIR823G.pcap"
    trees_list = MsgTree.build_tree_list(file_path)
    target_ip = "192.168.111.128"
    target_port = 80
    session = Session(
        target=Target(connection=TCPSocketConnection(target_ip, target_port)),
    )
    
    for index, couple in enumerate(trees_list):
        if couple[0].get_node("Method").data == b"GET":
            fuzz_get_static(msgtree=couple[0]  ,session = session, request_index=index)
        else:
            fuzz_post_static(msgtree=couple[0], etree=couple[1], session=session, request_index=index)
    # fuzz_get_static(msgtree=trees_list[0][0], session = session, request_index=1 )
    # fuzz_get_static(msgtree , request_index=1, session=session)
    # session.feature_check()

    session.fuzz()
