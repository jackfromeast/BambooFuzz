"""

    解析树对象: MsgTree
    用途: 将 pcap 文件数据包存入树形结构
    主要方法: build_tree_list, build_login_tree

"""
# -*- coding: utf-8 -*-
import re
import xml.etree.ElementTree as ET

# 应修改为上级目录下boofuzz！！！！
from boofuzz import *

from .treelib import Tree
from .utils import *


# 类定义
class MsgTree(Tree):
    '''
    报文解析存储树
    '''
    # 初始化
    def initial(self):
        """初始化root(msg)结点及三大结点requestLine, Headers, optContent.
        返回 msgtree
        """
        tree = MsgTree()
        tree.create_node(tag="msg", identifier="msg", data=100)
        tree.create_node(tag="requestLine", identifier="requestLine", data=200, parent="msg")
        tree.create_node(tag="Headers", identifier="Headers", parent="msg")
        tree.create_node(tag="optContent", identifier="optContent", parent="msg")
        return tree
    
    # 装饰器静态方法
    @staticmethod
    # 生成requestLine树
    def get_requestLine(header_dic={}):
        """
        初始化requestLine子树. 
        返回 msgtree.
        """
        new_tree = Tree()
        method = header_dic["Method"]
        Path = header_dic["Path"]
        
        # 是否含有'?', 判断是否包含参数部分
        # 从Path分离parameter部分
        if b"?" in Path:
            # 正则匹配
            Path = Path.decode()
            True_Path = re.search(r"[\s\S]*\?", Path).group()
            True_Path = True_Path[:-1]
            True_Path = True_Path.encode()
        else:
            True_Path = Path

        # 获取URL和Version
        url = get_url(header_dic)
        version = header_dic["Http-Version"]

        # 生成Method, URL, version结点
        new_tree.create_node(tag="requestLine", identifier="requestLine")
        new_tree.create_node(tag="Method", identifier="Method", data=method, parent="requestLine")
        new_tree.create_node(tag="URL", identifier="URL", parent="requestLine")
        new_tree.create_node(tag="version", identifier="version", data=version, parent="requestLine")
        
        # 在URL下生成Path和param分支
        new_tree.create_node(tag="Path", identifier="Path", data=True_Path, parent="URL")
        
        # path分割
        path_list = path_split(True_Path.decode())
        # 遍历list, 生成 path_n 叶子结点
        for index, path in enumerate(path_list):
            tag = "path_" + str(index+1)
            new_tree.create_node(tag = tag, identifier=tag, data=path, parent="Path")

        # 如果为GET方法, 生成parameter分支
        if method_is_get(method):
            params = get_params(url)
            new_tree.create_node(tag="parameters", identifier="parameters", parent="URL")
            index = 0
            # 遍历list, 生成 param_n 叶子结点
            for key, param in params.items():
                index = index + 1
                tag = "param_" + str(index)
                new_tree.create_node(tag=tag, identifier=key, data=param, parent="parameters")
        else:
            pass

        return new_tree



    @staticmethod
    # 生成Headers树
    def get_headers(header_dic={}):
        """
        初始化Headers子树. 
        返回 msgtree.
        """
        new_tree = Tree()
        new_tree.create_node(tag="Headers", identifier="Headers")
        headers = get_headers4tree(header_dic)
        # 字典拆分
        header_keys = list(headers.keys())
        header_values = list(headers.values())
        
        # 确保value部分不包括 '\r\n'
        for i, v in enumerate(header_values):
            if v[-4:] == b'\r\n':
                header_values[i] = v[:-4]

        index = 0
        # 遍历生成Header结点
        for key, value in zip(header_keys, header_values):
            index = index + 1
            new_tree.create_node(tag=str(key), identifier=str(key), data=str(value, encoding="utf-8" ), parent="Headers")
        
        return new_tree


    @staticmethod
    # 生成optContent树
    def get_optContent(payload):
        """
        初始化optContent子树. 
        返回 msgtree, etree.
        """
        new_tree = Tree()
        # 数据类型为xml or soap, 存入对应version
        if "?xml" in payload:
            # etree解析
            new_etree = ET.fromstring(payload)
            new_tree.create_node(tag = "optContent", identifier="optContent")
            new_tree.create_node(tag = "xml", identifier="xml",parent="optContent")

            # 正则匹配xml version
            xml_statement = re.search("(<\?[\s\S]*\?>)", payload)
            xml_statement = xml_statement.group(0)
            payload = payload.replace(xml_statement, "")
            
            # 建立xml-info
            new_tree.create_node(tag="xml-info", identifier="xml-info", parent="xml", data=xml_statement)
        
        # 数据类型为data键值对, 存入对应data
        else:
            new_etree = None
            dic = str_to_dic(payload)
            new_tree.create_node(tag = "optContent", identifier="optContent")
            new_tree.create_node(tag = "data", identifier="data",parent="optContent")
            # 遍历字典存入
            for key, value in dic.items():
                new_tree.create_node(tag = key, identifier= key, data=value, parent="data")

        return new_tree, new_etree
    

    # 获取表亲结点
    def cousin(self, Node):
        """ 
        根据Node的表亲, 构建存放结点list. 
        返回 list. 
        """
        parent = self.parent(Node)
        cousins = self.children(parent.tag)
        return cousins
        

    # Dictionary generated from leaf nodes
    # def fuzz_element_dic(self):
    #     fuzz_element = {}
    #     leaves = self.leaves()
    #     fuzz_element["Path"] = self.get_node("Path").data
    #     for leave in leaves:
    #         fuzz_element[leave.tag] = leave.data
    #     return fuzz_element
    
    @staticmethod
    # 构建树群
    def build_tree_list(file_path):
        """ 
        根据pcap文件, 构建存放树list. 
        返回 list. 
        """
        headers = get_headers(file_path)
        payloads = get_payloads(file_path)
        tree_list = []
        for header, payload in zip(headers, payloads):
            # Msgtree 对象
            # couple存放树, GET:[msgtree], POST:[msgtree, etree]
            # 如果为GET类型
            if header["Method"] == b"GET":
                couple = []
                tree = MsgTree()
                # 根节点
                msgtree = tree.initial()

                # requestLine 和 Headers 分支
                requestLine = MsgTree.get_requestLine(header)
                headers = MsgTree.get_headers(header)

                # 子树接入
                msgtree.merge("requestLine", requestLine)
                msgtree.merge("Headers", headers)

                # 填入树群
                couple.append(msgtree)
                tree_list.append(couple)
                # msgtree.show()

            else:
                couple = []
                tree = MsgTree()
                # 根节点
                msgtree = tree.initial()

                # requestLine 和 Headers 和 optContent 分支
                requestLine = MsgTree.get_requestLine(header)
                headers = MsgTree.get_headers(header)
                optContent, etree = MsgTree.get_optContent(payload)

                # 子树接入
                msgtree.merge("requestLine", requestLine)
                msgtree.merge("Headers", headers)
                msgtree.merge("optContent", optContent)
                couple.append(msgtree)
                couple.append(etree)

                # 填入树群
                tree_list.append(couple)
                # msgtree.show()
        return(tree_list)
    

    def build_login_tree(file_path):
        """
        用于获取流程中第一个 pcap 文件的 Login 请求数据包
        返回 list
        """
        trees_list = MsgTree.build_tree_list(file_path)
        login = []
        trees_list.sort(key=lambda i:len(i), reverse=True)
        for couple in trees_list:
            if len(couple) == 2:
                login = couple
                break
            elif couple[0].get_node("parameters"):
                login = couple
                break
        return login



        