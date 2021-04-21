"""
    fuzz流程测试脚本

    不包括Moniter部分，仅用于测试以下内容：
        + 变异算法的正确性
        + 数据报文序列化与反序列化的正确性
        + 对于响应内容的监控
"""
import sys
import os
sys.path.insert(1,os.path.abspath('./boofuzz-src/'))  # 优先调用boofuzz再开发的模块而不是之前的第三方模块
sys.path.insert(1,os.path.abspath('./'))

from boofuzz import TCPSocketConnection, Session, Target, NetworkMonitor, ProcessMonitor, s_initialize, FuzzLoggerText, FuzzLoggerCsv, s_string, s_delim, s_static, s_get, s_block, s_size, s_group
from pcapParse.tree2message import fill_session

def main():
    target_ip = "192.168.0.1"
    target_port = 80
    login_packs = './spider/packets/dlink_dir822_login.pcap'
    main_packs = './spider/packets/dlink_dir822_main.pcap'
    # netmon_port = 26001
    # procmon_port = 26002


    """
    自定义Callback Monitor
    用于对响应包进行监测，查看其是否包含命令注入的结果返回
    """
    def response_check(target, fuzz_data_logger, node, session, edge, *args, **kwargs):
        try:
            response = target.recv(10000)
        except:
            print("Unable to connect. Target is down. Exiting.")
            exit(1)
        
        # check the response

        # if something intriguing found:
            # alert through Crash!!!


    """
    登陆cookie或token获取
    Session pre_send callback adds token to every message
    Session post_test_case callback is used to renew the token between each test
    """
    def rerender_cookie(target, fuzz_data_logger, session, sock):
        auth_response = requests.post("http://server_address/login", data={
            "_username": "my_username",
            "_password": "my_password"
        })

        global auth_token
        auth_token = auth_response.json()['token']

    def session_pre_send_callback(target, fuzz_data_logger, session, sock):
        session.fuzz_node.names['Cookie-Value']._value = f"Cookie: {auth_token}"
        return session.fuzz_node.render()


    fuzz_log_file = open('./fuzz-results/dlink-dir822-fuzzlog.csv', 'w')

    session = Session(
        target=Target(connection=TCPSocketConnection(target_ip, target_port)),
        sleep_time=0.2,
        fuzz_loggers=[FuzzLoggerText(), FuzzLoggerCsv(file_handle=fuzz_log_file)]
    )

    session = fill_session(session, login_packs, main_packs)

    session.fuzz()

    fuzz_log_file.close()


if __name__ == "__main__":
    main()