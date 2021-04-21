"""

    序列化对象: Serializer
    用途: 将 msgtree 和 etree 序列化生成boofuzz内容
    主要方法: fuzz_get_static, fuzz_post_static

"""
# -*- coding: utf-8 -*-
# 应修改为上级目录下boofuzz！！！！
from boofuzz import *
from .utils import *
from .MsgTree import MsgTree


class Serializer(object):
    """
    序列化生成 boofuzz 报文
    """
    
    def fuzz_get_static(self, msgtree, request_index, session):
        """
        Fuzz GET请求
        """
    
        # boofuzz初始化
        s_initialize(name=f"Request-{request_index}")

        # Request-Line block
        with s_block("Request-Line"):

            # Line-1 requestline 部分
            self.__fuzz_requestline(msgtree=msgtree, method='GET')

            # Line-n Headers 部分, 遍历生成 header 部分
            self.__fuzz_headers(msgtree=msgtree)

        session.connect(s_get(f"Request-{request_index}"))
        # if request_index == 'login':
        #     session.connect(s_get(f"Request-{request_index}"))
        # else:
        #     session.connect(s_get(f'Request-login'), s_get(f'Request-{request_index}'))


    def fuzz_post_static(self, msgtree, etree, request_index, session):
        """
        Fuzz POST请求
        """
    
        # boofuzz初始化
        s_initialize(name=f"Request-{request_index}")
        
        # Request-Line block
        with s_block("Request-Line"):
            
            # Line-1 requestline 部分
            self.__fuzz_requestline(msgtree=msgtree, method='POST')
 
            # Line-n Headers 部分, 遍历生成 header 部分
            self.__fuzz_headers(msgtree=msgtree)

        # Payload block
        with s_block("Payload"):
            
            # payload 部分
            self.__fuzz_payload(msgtree=msgtree, etree=etree)

        session.connect(s_get(f"Request-{request_index}"))
        # if request_index == 'login':
        #     session.connect(s_get(f"Request-{request_index}"))
        # else:
        #     session.connect(s_get(f'Request-login'), s_get(f'Request-{request_index}'))



    def __traverse_soap(self, etree, index=-1):
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
                self.__traverse_soap(child, index)        
        # 否则输出最内层的值
        else:
            s_string(value = str(etree.text), brother=3, level=3)
            # s_string(value = str(etree.text))
        # 如果为Body,输入固定字符;否则输出结束标签
        if "Body" in etree.tag:
            s_static(value = (f"</soap:Body>"))
        else:
            s_static(value = (f"</{etree_tag}>") )

    def __traverse_xml(self, etree, index=-1):
        """ 
        遍历xml报文, 生成对应boofuzz内容. 
        """
        index = index + 1 
        s_static(value = ((index-1) * "\t" + f"<{etree.tag}>" + "\n"))
        if etree.getchildren():
            children = etree.getchildren()
            for child in children:
                self.__traverse_xml(child, index)
        else:
            s_static(value = (index+1) *"\t")
            # s_string(value = str(etree.text))
            s_string(value = str(etree.text), brother=3, level=3)
        s_static(value = ( (index-1) * "\t" + f"</{etree.tag}>" + "\n") )

    def __fuzz_requestline(self, msgtree, method):
        """
        根据requestLine生成boofuzz内容
        """
        paths = msgtree.children("Path")

        # Line-1 Method 部分
        s_group("Method", [f"{method}"])
        s_delim(name="space-1", value=" ", fuzzable=False)

        # Line-1 Path 部分, 遍历生成 path 部分
        s_static("/", name="Request-URI")
        for index, path in enumerate(paths):
            index = str(index)
            # s_string(name="path"+index, value=path.data)
            s_string(name="path"+index, value=path.data, brother=len(msgtree.cousin(path.identifier)) , level=msgtree.level(path.identifier))
            if int(index) < (len(paths)-1):
                s_static(name="path_delim-" + index, value="/" )
        

        if method == 'GET':
            s_delim(name="mark", value="?", fuzzable=False)
            params = msgtree.children("parameters")
            for index, param in enumerate(params):
                s_static(name=f"key-{index}", value=param.identifier)
                s_static(name=f"equal_sign-{index}", value="=")
                # s_string(name=f"value-{index}", value=param.data)
                s_string(name=f"value-{index}", value=param.data, brother=len(msgtree.cousin(param.identifier)) , level=msgtree.level(path.identifier))
                # 非最终键值对输出 '&' 作为连接符
                if index < len(params)-1:
                    s_static(name=f"param_delim-{index}", value="&")
        
        s_delim(name="space-2", value=" ", fuzzable=False)


        # Line-1 version 部分
        s_static(name="Version", value=msgtree.get_node("version").data)
        s_static(name="Line-CRLF", value="\r\n")

    def __fuzz_headers(self, msgtree):
        """
        根据Headers生成boofuzz内容
        """
        headers = msgtree.children("Headers")
        no_fuzz_list = ["Host", "Connection", "Accept-Encoding", "Accept-Language"]

        # Line-n Headers 部分, 遍历生成 header 部分
        for index, header in enumerate(headers):
            # 防止报文截断，获取 payload 长度
            if header.tag == "Content-Length":
                s_static(name=f"header-key-{index}", value=header.tag)
                s_static(name=f"delim--{index}", value=": ")
                s_size(block_name="Payload",fuzzable=False, output_format="ascii")
            # 判断是否为非 fuzz 字段 确定 static 和 string
            elif header.tag in no_fuzz_list:
                s_static(name=f"header-key-{index}", value=header.tag)
                s_static(name=f"delim--{index}", value=": ")
                s_static(name=f"header-value-{index}", value=header.data)
            else:
                s_static(name=f"header-key-{index}", value=header.tag)
                s_static(name=f"delim--{index}", value=": ")
                if header.data[-2:] == '\r\n':
                    header.data = header.data[:-2]
                # s_string(name=f"header-value-{index}", value=header.data)
                s_string(name=f"header-value-{index}", value=header.data, brother=len(msgtree.cousin(header.identifier)) , level=msgtree.level(header.identifier))
            s_static(name=f"line_delim--{index}", value="\r\n" )
        s_static(name="Request-Line-CRLF", value="\r\n")

    def __fuzz_payload(self, msgtree, etree):
        """
        根据payload生成boofuzz内容
        """
        # 判断 etree 是否为空: 空 data 生成, 非空 etree 遍历
        if etree != None:
            # 生成 msgtree xml-info 部分
            node = msgtree.get_node("xml-info")
            s_static(name="xml-info", value=node.data)
            
            # 判断etree内容: 非 soap 协议, 遍历生成 xml 报文, 否则生成 soap 报文
            if "soap" not in etree.tag:
                s_static(value="\n")
            # case 1: xml
                self.__traverse_xml(etree)
            # case 2: soap
            else:
                body = etree.getchildren()    
                s_static('<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">')
                self.__traverse_soap(body[0])
                s_static("</soap:Envelope>")
            
        else:
            datas = msgtree.leaves("data")
            # 遍历 msgtree 的 data 部分
            for index, data in enumerate(datas):
                s_static(name = f"data-key-{index}", value=data.tag)
                s_static(value = "=")
                # s_string(name = f"data-value-{index}", value=data.data)
                s_string(name = f"data-value-{index}", value=data.data, brother=len(msgtree.cousin(data.identifier)) , level=msgtree.level(data.identifier))
            s_static(name = "CRLF", value = "\r\n")
    

def fill_session(session, file_path_l, file_path_m):
    """
    session 填充
    返回 session
    """
    # 对象生成
    serializer = Serializer()

    # 连接第一个login结点
    login_tree = MsgTree.build_login_tree(file_path_l)

    # 根据请求类型进行fuzz
    if login_tree[0].get_node("Method").data == b"GET":
        serializer.fuzz_get_static(msgtree=login_tree[0], session=session, request_index='login')
    else:
        serializer.fuzz_post_static(msgtree=login_tree[0], etree=login_tree[1], session=session, request_index='login')

    # 连接后续结点至login
    trees_list = MsgTree.build_tree_list(file_path_m)

    # 根据请求类型进行fuzz
    for index, couple in enumerate(trees_list):
        if couple[0].get_node("Method").data == b"GET":
            serializer.fuzz_get_static(msgtree=couple[0]  ,session = session, request_index=index)
        else:
            serializer.fuzz_post_static(msgtree=couple[0], etree=couple[1], session=session, request_index=index)
    
    return session


if __name__ == "__main__":
    '''
    fuzz example
    '''
    # file_path = "Dlink-DIR823G.pcap"
    # # 对象初始化
    # msgtree = MsgTree()
    # serializer = Serializer()
    
    # # 获取树表
    # trees_list = msgtree.build_tree_list(file_path)

    # # 目标 ip 及 port
    # target_ip = "192.168.111.128"
    # target_port = 80

    # # 会话 session
    # session = Session(
    #     target=Target(connection=TCPSocketConnection(target_ip, target_port)),
    # )

    # for index, couple in enumerate(trees_list):
    #     if couple[0].get_node("Method").data == b"GET":
    #         serializer.fuzz_get_static(msgtree=couple[0]  ,session = session, request_index=index)
    #     else:
    #         serializer.fuzz_post_static(msgtree=couple[0], etree=couple[1], session=session, request_index=index)
    # session.feature_check()
    # # fuzz start
    # session.fuzz()
