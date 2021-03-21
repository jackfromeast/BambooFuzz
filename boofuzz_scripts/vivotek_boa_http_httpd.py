from boofuzz import TCPSocketConnection, Session, Target, NetworkMonitor, ProcessMonitor, s_initialize, FuzzLoggerText, FuzzLoggerCsv, s_string, s_delim, s_static, s_get, s_block, s_size, s_group


def main():
    target_ip = "10.211.55.4"
    target_port = 80
    netmon_port = 26001
    procmon_prot = 26002

    # 网络服务监控Moniter（粒度过于粗）
    # netmon = NetworkMonitor(target_ip, netmon_port) 
    # netmon_options = {"log_path" : './pcap_history'}
    # netmon.set_options(**netmon_options)
    
    # 进程监控Moniter
    procmon = ProcessMonitor(target_ip, procmon_prot) 
    procmon_options = {
        "proc_name" : "qemu-arm",
        "start_commands": 'echo "127.0.0.1 Network-Camera localhost" >   /proc/sys/kernel/hostname && qemu-arm -L . ./usr/sbin/httpd',
        "cwd_path": '/home/apple/IoT_firmware_images/_CC8160-VVTK-0100d.flash.zip.extracted/_CC8160-VVTK-0100d.flash.pkg.extracted/_31.extracted/_rootfs.img.extracted/squashfs-root/'
        }
    procmon.set_options(**procmon_options)

    fuzz_log_file = open('boofuzz-results/vivotek_boa_http_httpd_fuzzlog.csv', 'w')

    session = Session(
        target=Target(connection=TCPSocketConnection(target_ip, target_port), monitors=[procmon]),
        sleep_time=0.5,
        fuzz_loggers=[FuzzLoggerText(), FuzzLoggerCsv(file_handle=fuzz_log_file)]
    )

    # s_initialize函数初始化一个命名为Request的块请求，并将之后所有定义的blocks和primitives添加到此块请求上
    s_initialize(name="Request")

    with s_block("Request-Line"):
        s_group("Method", ["POST"])
        s_delim(" ", name="space-1")
        s_string("/cgi-bin/admin/upgrade.cgi", name="Request-URI", fuzzable=False)
        s_delim(" ", name="space-2")
        s_string("HTTP/1.0", name="HTTP-Version", fuzzable=False)
        s_static("\n", name="Request-Line-CRLF")
        # s_string("Host:", name="Host-Line", fuzzable=False)
        # s_delim(" ", name="space-3")
        # s_string("example.com", name="Host-Line-Value", fuzzable=False)
        # s_static("\r\n", name="Host-Line-CRLF")
        s_static("Content-Length:", name="Content-Length-Header")
        s_string("", name="Content-Length-Value")
        # s_delim(" ", name="space-4")
        # s_size("Body-Content", output_format="ascii", name="Content-Length-Value")
        s_static("\r\n", "Content-Length-CRLF")
    s_static("\r\n", "Request-CRLF")

    # with s_block("Body-Content"):
    #     s_string("Body content ...", name="Body-Content-Value")

    # s_get函数用于返回会话中的一个请求
    # 当仅传递一个参数时，作为session.connect函数的简写，将该请求链接到会话图中的根节点
    session.connect(s_get("Request"))

    session.fuzz()

    fuzz_log_file.close()


if __name__ == "__main__":
    main()
