from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.expected_conditions import staleness_of
from selenium.common.exceptions import TimeoutException, InvalidSelectorException, InvalidArgumentException, UnexpectedAlertPresentException
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import re
import time
from generate_xpath import Xpath_Util

"""
基于beautifulSoup以及selenium的整站爬虫
其中beautiful用于对页面进行解析，seleniem用于模拟浏览器行为
"""

global req_urls
global wait_to_req

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
    # 返回请求页面中的innerHTML
    page = driver.execute_script("return document.body.innerHTML").encode('utf-8').decode('latin-1')

    return page


# 启动ChromeDriver
def initialize_driver():
    #Create a chrome session
    chrome_options = Options()
    # chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    prefs = { "profile.managed_default_content_settings.images": 2 }
    chrome_options.add_experimental_option("prefs", prefs)

    driver = webdriver.Chrome(executable_path='/usr/bin/chromedriver', chrome_options=chrome_options)

    return driver


def login(driver, xpaths):
    # username = input('Enter default username: ')
    # key = input('Enter passwaord: ')

    username = 'admin'
    key = ''

    # 遍历input标签，除button外
    for ele in xpaths[0].keys():
        if re.search(r'user | usr', ele) != None:
            user = driver.find_element_by_xpath(xpaths[0][ele])
            if user.get_attribute('value') != '':
                user.clear()
            user.send_keys(username)
    
        if re.search(r'pwd | passwaord', ele) != None:
            pwd = driver.find_element_by_xpath(xpaths[0][ele]) 
            pwd.send_keys(key)

    # 只有一个button可以点，默认为提交按钮
    if len(xpaths[1]) == 1:
        for ele in xpaths[1].keys():
            if click(driver, xpaths[1][ele]):
                return True # 默认页面刷新即为登陆成功，虽然有可能验证未通过而转跳其他页面 之后再解决
            else:
                print("The login page didn't update after click!")
                return False


# 查看页面刷新
class wait_page_load:
    def __init__(self, driver, timeout=1):
        self.driver = driver
        self.timeout = timeout
        
    def __enter__(self):
        self.old_page = self.driver.find_element_by_tag_name('html')
    
    def __exit__(self, *_):
        WebDriverWait(self.driver, self.timeout).until(staleness_of(self.old_page))


def click(driver, element_path):
    try:
        with wait_page_load(driver):
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
        print("Woo! Timeout and the page didn't update!")
        return False 

    return True # 页面已刷新


# 寻找当前页面的所有a标签
def find_all_a(page):
    hrefs = []
    soup = BeautifulSoup(page, 'html.parser')

    for k in soup.find_all('a'):
        try:
            hrefs.append(k['href'])
        except():
            continue
    
    return hrefs


# 寻找当前页面和子页面的所有Button并点击 递归实现（子页面即url不变但通过php或js实现内容变化之后的页面）
def find_and_click(driver, req_urls, wait_to_req):
    current_page = driver.execute_script("return document.body.innerHTML").encode('utf-8').decode('latin-1')
    buttons = get_all_XPath(driver, current_page)[1] # 当前页面的所有button的xpath的字典

    for button in buttons.values():
        current_url = driver.current_url
        # 点击button
        try:
            if click(driver, button):
                # 如果更新了url且不在req_urls和wait_to_req中
                if(driver.current_url != current_url and driver.current_url not in req_urls and driver.current_url not in wait_to_req):
                    driver.get(current_url) 
                    wait_to_req.append(driver.current_url)
                    print("[*] The wait_to_req list append: %s" % driver.current_url)
                    continue
                else:
                    find_and_click(driver, req_urls, wait_to_req)
            else:
                continue
        except(InvalidSelectorException):
            print("Woo! The button's xpath: %s seems not correct! Skip!" % button)
            continue


def main(login_url=None):
    # 网站的根url
    root_path = login_url
    if login_url == None:
        login_url = input("Please enter url:")

    print("[*] The Bamboo Web Crawler is set up to access %s" % login_url)

    req_urls = [] # 维护该站点已点击的页面url
    wait_to_req = [] # 维护该站点待请求的url序列

    driver = initialize_driver()

    # 请求login登陆页面
    print("[*] Resquesting the login page.")
    login_page = request(driver, login_url)

    elements_in_login = get_all_XPath(driver, login_page)

    # index页面模拟登陆
    login_flag = False
    while(login_flag == False):
        if login(driver, elements_in_login):
            login_flag = True
            print("[*] The Crawler login in successfully!")
        else:
            print("Woo, Failed to login in! Don't worry! Try again!")
    
    wait_to_req.append(driver.current_url)
    print("[*] The wait_to_req list append: %s" % driver.current_url)

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
        current_page = driver.execute_script("return document.body.innerHTML").encode('utf-8').decode('latin-1')

        # 更新待请求的url序列
        wait_to_req = wait_to_req + find_all_a(current_page)

        # 寻找当前页面及其子页面的所有Button并点击 
        # 注意此函数下driver的url是不变的，对应的是同一页面
        find_and_click(driver, req_urls, wait_to_req)
        
        print("[*] The crawler has clicked all the buttons on %s, Moving next!\n" % driver.current_url)

    print("[*] The crawler has done all his job! Bye!")
    driver.quit()


main("http://192.168.10.1/")

