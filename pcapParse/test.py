from MsgTree import MsgTree
from tree2message import Serializer
from boofuzz import *

if __name__ == "__main__":
    
    file_path = "1.pcap"
    trees_list = MsgTree.build_tree_list(file_path)
    target_ip = "192.168.111.128"
    target_port = 80
    session = Session(
        target=Target(connection=TCPSocketConnection(target_ip, target_port)),
    )
    serializer = Serializer()

    for index, couple in enumerate(trees_list):
        if couple[0].get_node("Method").data == b"GET":
            serializer.fuzz_get_static(msgtree=couple[0]  ,session = session, request_index=index)
        else:
            serializer.fuzz_post_static(msgtree=couple[0], etree=couple[1], session=session, request_index=index)
    # fuzz_get_static(msgtree=trees_list[0][0], session = session, request_index=1 )
    # fuzz_get_static(msgtree , request_index=1, session=session)
    # session.feature_check()

    session.fuzz()