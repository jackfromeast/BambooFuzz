import os
import subprocess
import signal
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.expected_conditions import staleness_of
from selenium.common.exceptions import TimeoutException, InvalidSelectorException, InvalidArgumentException, UnexpectedAlertPresentException, ElementNotInteractableException
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import re
import time
from selenium.common.exceptions import * 
from gen_xpath import Xpath_Util
from itertools import permutations


"""
基于beautifulSoup以及selenium的整站爬虫
其中beautiful用于对页面进行解析，seleniem用于模拟浏览器行为
"""

global req_urls
global wait_to_req

def stop_handler(signum, frame):
    os.killpg(os.getpgid(sni2.pid), signal.SIGTERM)
    os.killpg(os.getpgid(sni1.pid), signal.SIGTERM)

    exit(0)
    
# 如果爬虫被手动中断，发送终止信号到sniffer
signal.signal(signal.SIGINT, stop_handler)

# 获取一个页面的所有input和button标签的Xpath
def get_all_XPath(driver, a_page):
    # 初始化Soup
    soup = BeautifulSoup(a_page, 'html.parser')

    # 初始化Xpath解析器
    xpath_obj = Xpath_Util(driver)

    xpaths = xpath_obj.generate_xpath(soup)
    if len(xpaths) == 0:
        print ("No XPaths generated for the page:%s" % driver.current_url)
        return None

    return xpaths


# 使用webdriver发送请求，并返回请求页面
def request(driver, url):
    driver.get(url)

    # 返回请求页面中的HTML
    page = driver.execute_script("return document.documentElement.outerHTML").encode('utf-8').decode('latin-1')
    return page


# 启动ChromeDriver
def initialize_driver():
    #Create a chrome session
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    prefs = { "profile.managed_default_content_settings.images": 2 }
    chrome_options.add_experimental_option("prefs", prefs)
    #driver = webdriver.Firefox()
    driver = webdriver.Chrome(executable_path='./chromedriver', chrome_options=chrome_options)

    return driver


def login(driver, xpaths, parameter):
    """ 
    模拟用户登陆过程
    xpaths: 登陆界面的可交互标签的xpath
    parameter: 用户名密码对
    """
    login_url=driver.current_url
    regex = re.compile(r'[a-zA-z]+://[\d+\.]*/[^\s]+')
    match = regex.search(login_url) 
    # 如果不存在输入框或者登陆框
    if(len(xpaths[0]) == 0 or len(xpaths[1]) == 0):
        print("[debug] Didn't find where to send usr#pwd or where to click!")
        return False
    
    else:
        # 如果只有一个输入框，默认填入pwd
        if len(xpaths[0]) == 1:
            _send_keys(driver, xpaths[0]['input_0'], parameter['pwd'])

            # 遍历点击所有button
            for ele in xpaths[1].keys():
                if click(driver, xpaths[1][ele]):
                    if login_url==driver.current_url:
                        if match==None:#页面URL只有IP的情况
                            return True
                        else:
                            continue
                    else:
                        return True
                # 如果没有监测到页面刷新，判断是否登陆成功
                else:
                    print("[Debug] The login page didn't update after click! try again!")

        elif len(parameter)==2:
            # 将输入框排列组合填入keypair
            for tagset in permutations(xpaths[0].values(), 2):
                _send_keys(driver, tagset[0], parameter['user'])
                _send_keys(driver, tagset[1], parameter['pass'])
                print("cookie1:"+str(driver.get_cookies()))
                for ele in xpaths[1].keys():
                    if click(driver, xpaths[1][ele]): 
                        if login_url==driver.current_url:
                            if match==None:#页面URL只有IP的情况
                                return True
                            else:
                                continue
                        else:
                            return True
                    # 如果没有监测到页面刷新，判断是否登陆成功
                    else:
                        print("[Debug] The login page didn't update after click! try again!")
    
        elif len(parameter)==1:
            for key in xpaths[0].keys():
                pwd=driver.find_element_by_xpath(xpaths[0][key])
                try:
                    pwd.send_keys(parameter['pass'])
                except(ElementNotInteractableException):
                    pass
                for ele in xpaths[1].keys():
                    if click(driver, xpaths[1][ele]): 
                        if login_url==driver.current_url:
                            if match==None:#页面URL只有IP的情况
                                return True
                            else:
                                continue
                        else:
                            return True
                    # 如果没有监测到页面刷新，判断是否登陆成功
                    else:
                        print("[Debug] The login page didn't update after click! try again!")
                print("We can't find the login button!")
    return False


def _send_keys(driver, xpath, para):
    element = driver.find_element_by_xpath(xpath)
    try: 
        element.send_keys(para)
        return True
    except(ElementNotInteractableException):
        return False


class wait_page_load:
    def __init__(self, driver,past_page,timeout=4):
        self.driver = driver
        self.timeout = timeout
        self.past_page = past_page
      
    def __enter__(self):
        self.old_page = self.driver.find_element_by_tag_name('html')
    
    def __exit__(self, *_):
        time.sleep(self.timeout)
        current_page=self.driver.execute_script("return document.body.innerHTML").encode('utf-8').decode('latin-1')
        if(current_page==self.past_page):
            raise TimeoutException
            

def click(driver, element_path):
    try:
        past_page=driver.execute_script("return document.body.innerHTML").encode('utf-8').decode('latin-1')
        with wait_page_load(driver,past_page):
            driver.find_element_by_xpath(element_path).click()
            print("[*] The crawler has clicked button: %s"%element_path)
            
            # 判断是否有弹窗
            alert = EC.alert_is_present()(driver)
            if(alert):
                print("Woo! Came coross a alert and it said: %s" % alert.text)
                alert.accept()
                print("Accept it anyway!")
            else:
                pass

    # 超时，页面未刷新
    except(TimeoutException):
        print("[Debug] Timeout and the page didn't update!")
        return False 
    except(ElementNotInteractableException):
        print("[Debug] The button doesn't display or can't interact with!")
        return False

    return True # 页面已刷新


# 寻找当前页面的所有a标签
def find_all_a(page,req_urls,local_ip):
    hrefs = []
    soup = BeautifulSoup(page, 'html.parser')

    for k in soup.find_all('a'):
        try:
            if(k['href'] not in req_urls and local_ip in k['href']):
                hrefs.append(k['href'])
        except(KeyError):
            continue
    
    return hrefs


# 寻找当前页面和子页面的所有Button并点击 递归实现（子页面即url不变但通过php或js实现内容变化之后的页面）
def find_and_click(driver, req_urls, wait_to_req,ip):
    #current_page = driver.execute_script("return document.body.innerHTML").encode('utf-8').decode('latin-1')
    current_page = driver.execute_script("return document.documentElement.outerHTML").encode('utf-8').decode('latin-1')
    buttons = get_all_XPath(driver, current_page)[1] # 当前页面的所有button的xpath的字典

    for button in buttons.values():
        current_url = driver.current_url
        # 点击button
        try:
            #至少子页面有更新
            if click(driver, button):#至少子页面有更新
                # 如果更新了url且不在req_urls和wait_to_req中
                if(driver.current_url != current_url and driver.current_url not in req_urls and driver.current_url not in wait_to_req):
                    if(ip in driver.current_url):
                        wait_to_req.append(driver.current_url)
                        print("[*] The wait_to_req list append: %s" % driver.current_url)
                        driver.get(current_url) 
                        continue
                elif(driver.current_url != current_url and (driver.current_url in req_urls or driver.current_url in wait_to_req)):
                    driver.get(current_url) 
                    continue

                else:
                    find_and_click(driver, req_urls, wait_to_req,ip)
            else:
                continue
        except(InvalidSelectorException):
            print("[debug] The button's xpath: %s seems not correct! Skip!" % button)
            continue
    return True


def main(login_url, key_pair):
    # 网站的根url
    root_path = login_url
    if login_url == None:
        login_url = input("Please enter url:")

    print("[*] The Bamboo Web Crawler is set up to access %s" % login_url)
    local_ip=re.findall(r"\d+\.?\d+\.?\d+\.?\d+\.?\d*",login_url)
    req_urls = [] # 维护该站点已点击的页面url
    wait_to_req = [] # 维护该站点待请求的url序列

    # 初始化webdriver
    driver = initialize_driver()

    # 请求login登陆页面
    print("[*] Resquesting the login page.")
    login_page = request(driver, login_url)

    # 开启对Login界面请求的监听
    global sni1
    sni1 = subprocess.Popen("sudo python3 sniffer.py -filepath './packets/dlink_dir822_login.pcap' -name Loginsni", shell=True, cwd="/home/jackfromeast/bamboofuzz/spider", encoding="utf-8", preexec_fn=os.setsid)
    time.sleep(3) # 等待启动spider1

    elements_in_login = get_all_XPath(driver, login_page)
    # index页面模拟登陆
    login_flag = False
    while(login_flag == False):
        if login(driver, elements_in_login, key_pair):
            login_flag = True
            print("[*] The Crawler login in successfully!")
        else:
            print("[Debug] Failed to login in! Don't worry! Try again!")
    os.killpg(os.getpgid(sni1.pid), signal.SIGTERM)

    
    # 成功登陆后准备爬取整站，开启监听
    global sni2
    sni2 = subprocess.Popen("sudo python3 sniffer.py -filepath './packets/dlink_dir822_main.pcap' -name Sitesni -timeout 300", shell=True, cwd="/home/jackfromeast/bamboofuzz/spider", encoding="utf-8", preexec_fn=os.setsid)
    time.sleep(3) # 等待spider2启动

    wait_to_req.append(driver.current_url)
    print("[*] The wait_to_req list append: %s" % driver.current_url)
    req_urls.append(login_url)
    # 若待请求队列wait_to_req不为空
    while(len(wait_to_req) != 0):
        req_urls.append(driver.current_url)
        next_url = wait_to_req.pop(0)
        try:
            driver.get(next_url)
        # 如果请求的url的不正确或不完整
        except(InvalidArgumentException):
            driver.get(root_path + next_url)

        print("\n[*] The crawler start to click the buttons on %s" % driver.current_url)
        current_page = driver.execute_script("return document.documentElement.outerHTML").encode('utf-8').decode('latin-1')

        # 更新待请求的url序列
        wait_to_req = wait_to_req + find_all_a(current_page,req_urls,local_ip[0])
        wait_to_req = list(set(wait_to_req))

        # 寻找当前页面及其子页面的所有Button并点击 
        # 注意此函数下driver的url是不变的，对应的是同一页面
        find_and_click(driver, req_urls, wait_to_req,local_ip[0])
        
        print("[*] The crawler has clicked all the buttons on %s, Moving next!\n" % driver.current_url)

    print("[*] The crawler has done all his job! Bye!")
    driver.quit()
    os.killpg(os.getpgid(sni2.pid), signal.SIGTERM)





if __name__ =='__main__':
    main("http://192.168.0.1/", key_pair={'user': 'Admain', 'pass': ''})
    # main("http://192.168.0.1/Login.html", key_pair={'pass': ''})
