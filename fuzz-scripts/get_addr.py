import r2pipe
import json

class addrFinder:
    """
    Reverse the binary and find taint source addr & taint sink addr.
    """
    def __init__(self, binary_path,
                 source_list):
        self.binary_path = binary_path
        self.source_list = source_list

        self.sink_func = {
            "injectionFunc":['system', 'exec', 'popen', 'sprintf', 'snprintf'],
            "overflowFunc": ['strcpy','memcpy','strncpy','strcat'],
            "leakFunc": ['read','fread','fscanf','fgetc','fgets','vfscanf']
        }

        self.source_addrs = {}
        self.sink_func_addrs = {"injectionFunc":{},
                                "overflowFunc":{},
                                "leakFunc":{}}

        self.r2 = None
    
    def find(self):
        self.r2 = r2pipe.open(self.binary_path)
        self.r2.cmd('aa') # 二进制文件分析

        self.find_source_addr()
        self.find_sink_func_addrs()

        return self.source_addrs, self.sink_func_addrs

    def find_source_addr(self):
        if self.r2 == None:
            print("Didn't setup the r2.")
            return None

        # 初始化字典
        for source_str in self.source_list:
            self.source_addrs[source_str] = 0x000000

        all_strings = self.r2.cmdj('izj')

        for aString in all_strings:
            if aString['string'] in self.source_list:
                self.source_addrs[aString['string']] = hex(aString["vaddr"])
    

    def find_sink_func_addrs(self):
        if self.r2 == None:
            print("Didn't setup the r2.")
            return None
        
        all_funcs = self.r2.cmdj('aflj')

        for aFunc in all_funcs:
            for key, value in self.sink_func.items():
                for func in value:
                    if aFunc['name'].find(func) != -1:
                        self.sink_func_addrs[key][func] = hex(aFunc["offset"])


if __name__ == '__main__':
    addr_finder = addrFinder('./cgibin', ['ACTIONS', 'USER', 'PASSWD', 'CAPTCHA', 'HTTP_COOKIE', 'EVENT', 'HTTP_REFERER','HTTP_HOST','Path'])
    (source_addrs, sink_func_addrs) = addr_finder.find()

    print(source_addrs)
    print(sink_func_addrs)
        

        


    


