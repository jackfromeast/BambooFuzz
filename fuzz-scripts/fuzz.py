"""
    fuzz测试脚本

    不包括Moniter部分，仅用于测试以下内容：
        + 变异算法的正确性
        + 数据报文序列化与反序列化的正确性
        + 对于响应内容的监控
"""
import sys
import os
sys.path.insert(1,os.path.abspath('./boofuzz-src/'))  # 优先调用boofuzz再开发的模块而不是之前的第三方模块
sys.path.insert(1,os.path.abspath('./'))
from boofuzz import *
from boofuzz.exception import BoofuzzTargetConnectionReset
from pcapParse.MsgTree import MsgTree
from pcapParse.tree2message import Serializer


class BambooFuzzer(object):
    """
        针对Session Target的模糊测试器
    """
    def __init__(self, target_info):
        self.target_ip = target_info['target_ip']
        self.target_port = target_info['target_port']
        self.login_packs = target_info['login_packs']
        self.main_packs = target_info['main_packs']
        self.netmon_port = target_info['netmon_port']
        self.procmon_port = target_info['procmon_port']
        self.fuzz_log_file = target_info['log_file']

        self.session = None
    
    def fuzz(self):
        """
            主程序，开启对目标的模糊测试
        """
        self.__init_session()
        self.__add_callbacks()

        self.__gen_seed_requests()

        if self.__connect_session_graph():
            self.session.fuzz()
        
        self.fuzz_log_file.close()


    def __init_session(self):
        """
            初始化会话
        """

        self.fuzz_log_file = open(self.fuzz_log_file, 'w')

        self.session = Session(
            target = Target(connection=TCPSocketConnection(self.target_ip, self.target_port)),
            fuzz_loggers = [FuzzLoggerText(), FuzzLoggerCsv(file_handle=self.fuzz_log_file)],
            ignore_connection_reset = True,
            ignore_connection_aborted = True
        )
    

    def __add_callbacks(self):
        """
            添加callback回调函数
        """

        def response_check(target, fuzz_data_logger, session, sock, *args, **kwargs):
            """
                自定义Callback Monitor
                对响应包进行监测，查看其是否包含命令注入的结果返回
            """
            check_flag = True
            try:
                response = target.recv()
                response = bytes.decode(response)

            except(BoofuzzTargetConnectionReset):
                fuzz_data_logger.log_check('raise BoofuzzTargetConnectionReset, Cannot receive any data.')
                fuzz_data_logger.log_check('Pass response_check callback.')
                check_flag = False
                
            except(UnicodeDecodeError):
                fuzz_data_logger.log_check('raise UnicodeDecodeError.')
                fuzz_data_logger.log_check('Pass response_check callback.')
                check_flag = False

            if check_flag:  
                fuzz_data_logger.log_check('Verifying response contains inject commands exec result.')
                potential_results_lib = ['Linux', 'FoundABug!!!', '127.0.0.1 is alive!']

                for potential_res in potential_results_lib:
                    if response.find(potential_res) != -1:
                        fuzz_data_logger.log_fail('Response: "%s" containing "%s" which is highly suspected! Manual Check Is Needed!' % (response, potential_res))
                        break

                fuzz_data_logger.log_pass()

        self.session.register_post_test_case_callback(response_check)


    def __gen_seed_requests(self):
        """
            实例化种子报文为Request blocks
            定义的Seed Request将被添加到Requests全局变量中
        """
        # 实例化序列化器
        serializer = Serializer()
        msgtree = MsgTree()

        # 处理第一个login结点
        login_tree = msgtree.build_login_tree(self.login_packs)

        # 如果login请求报文为GET请求
        if login_tree[0].get_node("Method").data == b"GET":
            serializer.fuzz_get_static(msgtree=login_tree[0], request_index='login')
        else:
            serializer.fuzz_post_static(msgtree=login_tree[0], etree=login_tree[1], request_index='login')

        # 处理后续结点
        trees_list = msgtree.build_tree_list(self.main_packs)

        for index, couple in enumerate(trees_list):
            if couple[0].get_node("Method").data == b"GET":
                serializer.fuzz_get_static(msgtree=couple[0]  , request_index=index)
            else:
                serializer.fuzz_post_static(msgtree=couple[0], etree=couple[1], request_index=index)
    

    def __connect_session_graph(self):
        """
            连接各个请求节点，构建会话图
        """
        if self.session == None:
            return False

        # 将跟登陆节点连接到根节点
        self.session.connect(s_get('Request-login'))

        for r_name in REQUESTS.keys():
            self.session.connect(s_get('Request-login'), s_get(r_name))
        
        with open('./fuzz-scripts/session.png', 'wb') as fs:
            fs.write(self.session.render_graph_graphviz().create_png())
        
        return True
    

if __name__ == "__main__":

    target_info = {
        'target_ip': "192.168.0.1",
        'target_port': 80,
        'login_packs': './spider/packets/dlink_dir822_login.pcap',
        'main_packs': './spider/packets/dlink_dir822_main.pcap',
        'netmon_port': 26001,
        'procmon_port': 26002,
        'log_file': './fuzz-results/dlink-dir822-fuzzlog.csv'
    }

    bamboofuzzer = BambooFuzzer(target_info)
    bamboofuzzer.fuzz()
    