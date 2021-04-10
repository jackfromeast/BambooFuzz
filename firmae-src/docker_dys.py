#!/usr/bin/env python3

import sys
import threading
import subprocess as sp
import time
import os
import signal
import scripts.util as util
import multiprocessing as mp
import logging, coloredlogs
coloredlogs.install(level=logging.DEBUG)
coloredlogs.install(level=logging.INFO)



class docker_helper:
    def __init__(self, firmae_root,containern):
        self.firmae_root = firmae_root
        self.container_name = containern


    def run_core(self,brand,firmware_path,mode="-c"): 
        if mode == "-c":
# """docker run -p 90:80 -dit --rm \\
            cmd = """docker run -dit \\
                    -v /dev:/dev \\
                    -v {0}:/work/FirmAE \\
                    --privileged=true \\
                    --name {1} \\
                    dys""".format(self.firmae_root,
                                    self.container_name)
            print(cmd)
            sp.check_output(cmd, shell=True)

            logging.info("[*] {} emulation start!".format(self.container_name))

            #wait container start    
            time.sleep(2)     

        cmd = "docker exec  {0} ".format(self.container_name)
        cmd += "bash -c \"cd /work/FirmAE && "
        cmd += "./run.sh -d {0} {1}  ".format(brand,
                                           self.container_name)
        cmd += "2>&1 > /work/FirmAE/scratch/{0}.log".format(self.container_name)
        cmd += "\" &"
        print(cmd)

        sp.check_output(cmd, shell=True)

        firmware_log = os.path.join(self.firmae_root, "scratch", self.container_name + ".log")

      #检查是否成功
        while 1:
            with open(firmware_log) as f:
                words = f.read()
                if words.find("container failed") != -1:
                    logging.error("[-] %s container failed to connect to the hosts' postgresql")
                    return -1
                elif words.find("true true") != -1:
                    logging.error("successful simulation!")
                    return 1
            time.sleep(5)

def print_usage(argv0):
    print("[*] Usage")
    print("sudo %s -c|-s [brand] [firmwre_name]" % argv0)
    return

def runner(args):
    (dh, mode ,brand, firmware) = args
    if os.path.isfile(firmware):
        docker_name = dh.run_core(brand,firmware,mode)
    else:
        logging.error("[-] Can't find firmware file")

def main():
    #判断输入是否有问题
    if len(sys.argv) != 4 or os.geteuid() != 0:
        print_usage(sys.argv[0])
        exit(1)
    
    #拿到一个docker容器
    containern = sys.argv[-1]
    firmae_root=os.path.abspath('.')
    dh = docker_helper(firmae_root,containern)

    if not os.path.exists(os.path.join(firmae_root, "scratch")):
        os.mkdir(os.path.join(firmae_root, "scratch"))

    #组建一个启动命令
    mode = sys.argv[1]
    brand = sys.argv[2]
    firmware_path = os.path.abspath(sys.argv[3])
    argv = (dh,mode,brand,firmware_path)
    runner(argv)

        
if __name__ == "__main__":
    main()
