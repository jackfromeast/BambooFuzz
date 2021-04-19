# -*- coding: utf-8 -*-
import re
import sys
sys.path.append("..")
import xml.etree.ElementTree as ET

from boofuzz import *

from treelib import Tree
from utils import *


class MsgTree(Tree):

    
    # initialize msgtree
    def initial(self):
        tree = MsgTree()
        tree.create_node(tag="msg", identifier="msg", data=100)
        tree.create_node(tag="requestLine", identifier="requestLine", data=200, parent="msg")
        tree.create_node(tag="Headers", identifier="Headers", parent="msg")
        tree.create_node(tag="optContent", identifier="optContent", parent="msg")
        return tree
    
    @staticmethod
    # Generate 'requestLine' branch
    def get_requestLine(header_dic={}):
        new_tree = Tree()
        method = header_dic["Method"]
        Path = header_dic["Path"]
        if b"?" in Path:
            Path = Path.decode()
            True_Path = re.search(r"[\s\S]*\?", Path).group()
            True_Path = True_Path[:-1]
            True_Path = True_Path.encode()
        else:
            True_Path = Path
        url = get_url(header_dic)
        version = header_dic["Http-Version"]
        new_tree.create_node(tag="requestLine", identifier="requestLine")
        new_tree.create_node(tag="Method", identifier="Method", data=method, parent="requestLine")
        new_tree.create_node(tag="URL", identifier="URL", parent="requestLine")
        new_tree.create_node(tag="version", identifier="version", data=version, parent="requestLine")
        
        # Generate Path branch and param branch based on URL
        new_tree.create_node(tag="Path", identifier="Path", data=True_Path, parent="URL")

        path_list = path_split(True_Path.decode())
        for index, path in enumerate(path_list):
            tag = "path_" + str(index+1)
            new_tree.create_node(tag = tag, identifier=tag, data=path, parent="Path")

        if method_is_get(method):
            params = get_params(url)
            new_tree.create_node(tag="parameters", identifier="parameters", parent="URL")
            index = 0
            for key, param in params.items():
                index = index + 1
                tag = "param_" + str(index)
                new_tree.create_node(tag=tag, identifier=key, data=param, parent="parameters")
        else:
            pass
        return new_tree

    @staticmethod
    # Generate 'Headers' branch 
    def get_headers(header_dic={}):
        new_tree = Tree()
        new_tree.create_node(tag="Headers", identifier="Headers")
        headers = get_headers_tree(header_dic)
        header_keys = list(headers.keys())
        header_values = list(headers.values())
        
        # 确保value部分不包括\r\n
        for i, v in enumerate(header_values):
            if v[-4:] == b'\r\n':
                header_values[i] = v[:-4]

        index = 0
        for key, value in zip(header_keys, header_values):
            index = index + 1
            new_tree.create_node(tag=str(key), identifier=str(key), data=str(value, encoding="utf-8" ), parent="Headers")
        
        return new_tree
    

    """!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"""
    # Generate 'optContent' branch 
    @staticmethod
    def get_optContent(payload):
        new_tree = Tree()
        if "?xml" in payload:
            new_etree = ET.fromstring(payload)
            new_tree.create_node(tag = "optContent", identifier="optContent")
            new_tree.create_node(tag = "xml", identifier="xml",parent="optContent")

            # match xml statement
            xml_statement = re.search("(<\?[\s\S]*\?>)", payload)
            xml_statement = xml_statement.group(0)
            payload = payload.replace(xml_statement, "")
            
            # xml statement
            new_tree.create_node(tag="xml-info", identifier="xml-info", parent="xml", data=xml_statement)

        else:
            new_etree = None
            dic = str_to_dic(payload)
            new_tree.create_node(tag = "optContent", identifier="optContent")
            new_tree.create_node(tag = "data", identifier="data",parent="optContent")
            for key, value in dic.items():
                new_tree.create_node(tag = key, identifier= key, data=value, parent="data")

        return new_tree, new_etree
    
    def cousin(self, Node):
        parent = self.parent(Node)
        cousins = parent.children()
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
    def build_tree_list(file_path):
        """ Generate the tree_list based on the file(pcap) """
        headers = get_headers(file_path)
        payloads = get_payloads(file_path)
        tree_list = []
        for header, payload in zip(headers, payloads):
            # MsgTree Object
            if header["Method"] == b"GET":
                couple = []
                tree = MsgTree()
                # MsgTree initial
                msgtree = tree.initial()
                # Generate requestLine branch and Headers branch
                requestLine = MsgTree.get_requestLine(header)
                headers = MsgTree.get_headers(header)
                msgtree.merge("requestLine", requestLine)
                msgtree.merge("Headers", headers)
                couple.append(msgtree)
                tree_list.append(couple)
                # msgtree.show()

            else:
                couple = []
                tree = MsgTree()
                # MsgTree initial
                msgtree = tree.initial()
                # Generate requestLine branch and Headers branch
                requestLine = MsgTree.get_requestLine(header)
                headers = MsgTree.get_headers(header)
                optContent, etree = MsgTree.get_optContent(payload)
                msgtree.merge("requestLine", requestLine)
                msgtree.merge("Headers", headers)
                msgtree.merge("optContent", optContent)
                couple.append(msgtree)
                couple.append(etree)
                tree_list.append(couple)
                # msgtree.show()
        return(tree_list)
        




        