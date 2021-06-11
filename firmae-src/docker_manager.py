import os
import sys
import re
import subprocess as sp 


#获得容器列表
def get_status():
    sp.check_output("docker ps -a > hhh",shell=True)
    regex = re.compile('\s\s+')
    dic = {}
    with open("hhh") as lines:
        for ids,line in enumerate (lines):
            if ids!=0:
                line = line.strip().replace("\"","")
                splits= regex.split(line)
                name,cid,status,timecreate = splits[-1],splits[0],splits[4],splits[3]
                dic[name] = [cid,status,timecreate]
    if len(dic.keys()) ==1:
        key = list(dic.keys())[0]
        if "Exited" in dic[key][1]:
                dic[key][1] = "Stoped"
        elif "Paused" in dic[key][1]:
            dic[key][1] = "Paused"
        elif "Up" in dic[key][1]:
            dic[key][1] = "Running"
        else:
            del dic[key]
    else:
        for k in dic:
            if "Exited" in dic[k][1]:
                dic[k][1] = "Stoped"
            elif "Paused" in dic[k][1]:
                dic[k][1] = "Paused"
            elif "Up" in dic[k][1]:
                dic[k][1] = "Running"
            else:
                del dic[k]
    return dic

#状态
cmds = {"check":"docker exec -it name /bin/bash","stop":"docker stop name","start":"docker start name","pause":"docker pause name","run":"docker run --name name -dit dys","rm":"docker rm name","unpause":"docker unpause name"}
#状态权限列表
modelimit = {"Stoped":["rm","start","return"],"Paused":["stop","unpause","return"],"Running":["pause","stop","return","check"]}

#执行容器控制命令
def runcmd(cmd,name):
    name = " "+name+" "
    print(cmds[cmd].replace(" name",name))
    if cmd == "check":
        os.system(cmds[cmd].replace(" name",name))
    else:sp.check_output(cmds[cmd].replace(" name",name),shell=True).decode().strip()


#返回容器状态
def return_mode(name):
    mode_dic = get_status()
    mode = mode_dic[name][1]
    return mode
    
#打印对单个容器操作的菜单
def print_menu(mode):
    if mode=="Stoped":
        print("***choice***\n>rm\n>start\n>return")
    elif mode=="Paused":
        print("***choice***\n>stop\n>unpause\n>return")
    elif mode=="Running":
        print("***choice***\n>check\n>pause\n>stop\n>return")

#列出所有容器名称
def listnames():
    mode_dic = get_status()
    namelist = list(mode_dic.keys())
    return namelist

#清除所有容器
def clear():
    try:
        sp.check_output("docker stop $(docker ps -q) > /dev/null 2>&1 ",shell=True)
    except sp.CalledProcessError as e:
        pass
    try:
        sp.check_output("docker rm $(docker ps -aq)  > /dev/null 2>&1 ",shell=True)  
    except sp.CalledProcessError as e:  
        pass
    
#主逻辑
def main():
    while(1):
        print("--------------------------------------------------------------------------------")
        namelist = listnames()
        print(namelist)
        ##过滤
        try:
            name = input("Please choose name \nOr input create\nOr just input clear\n>")
        except KeyboardInterrupt:
            print("")
            break
 
        #选择功能
        if name == "clear":
            clear()
            continue

        elif name == "create":
            yes = input("Are you sure to create a container\n>")
            if yes=="Y" or yes=="y" or yes=="yes":
                while(1):
                    puts = input("[firmwarename] [brand]\n>").split(" ")
                    firmware_path = os.path.abspath(puts[0])
                    if len(puts)!=2 or puts[0] in namelist or not os.path.isfile(firmware_path):
                        print("Wrong number or invaild name or Can't find firmware file!\n")
                        continue
                    # IID = sp.check_out("./scripts/util.py get_iid puts[0] 127.0.0.1",shell=True).decode().strip()
                    try:
                        sp.check_output("python3 docker_dys.py -c {0} {1}".format(puts[1],puts[0]),shell=True)
                    except sp.CalledProcessError as e: 
                        print("similation failed!") 
                        pass            
                    break
            continue

        if name =='' or not name in namelist:
            continue
        while(1):
            mode = return_mode(name)
            print("mode:{}\n".format(mode))
            print_menu(mode)
            cmdchoice = input()
            if cmdchoice not in modelimit[mode]:
                print("please input right cmd or the cmd limit")
                continue
            elif cmdchoice=="return":
                break
            else:
                signal = runcmd(cmdchoice,name)
                if signal == 0:
                    print("success!\n")
                break

main()
