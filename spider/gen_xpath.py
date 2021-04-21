from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException,InvalidSelectorException
from bs4 import BeautifulSoup
import bs4
import re
 
class Xpath_Util:
    "Class to generate the xpaths"
 
    def __init__(self, driver):
        "Initialize the required variables"
        self.driver = driver
        self.elements = None
        self.guessable_elements = ['input','button']#只关注两种元素
        self.known_attribute_list = ['id','name','placeholder','value','title','type','class','onclick'] #已知的元素属性列表
        # self.variable_names = []
        # self.button_text_lists = []#把button里显示的文字保存在这里
        self.input_xpaths = {}
        self.button_xpaths = {}
        self.xpaths = [self.input_xpaths, self.button_xpaths]
        self.language_counter = 1
        self.button_index=0
        self.input_index=0
    def generate_xpath(self,soup):
        "generate the xpath and assign the variable names"
        result_flag = False
        for guessable_element in self.guessable_elements:
            self.elements = soup.find_all(guessable_element)#这里只找button或input元素
            for element in self.elements:
                result_flag = False #每次取出一个新的元素都应该初始化这个标签
                if (not element.has_attr("type")) or (element.has_attr("type") and element['type'] != "hidden"):#如果元素没有type或者type不被隐藏
                    #这里用每个已知属性试一下
                    for attr in self.known_attribute_list:
                        if element.has_attr(attr):#这里对一些常见属性进行判断
                            locator = self.guess_xpath(guessable_element,attr,element)
                            try:
                                if len(self.driver.find_elements_by_xpath(locator))==1:
                                    result_flag = True
                                    if element['type'] == 'button' or element['type'] == 'submit':#把button的字典存在一个字典里面去
                                        self.button_xpaths["%s_%d"%(guessable_element, self.button_index)] = "%s"%(locator.encode('utf-8').decode('latin-1'))
                                        self.button_index+=1
                                    else:
                                        self.input_xpaths["%s_%d"%(guessable_element, self.input_index)] = "%s"%(locator.encode('utf-8').decode('latin-1'))
                                        self.input_index+=1
                                    break       
                            except(InvalidSelectorException):
                              pass  
                    if(result_flag==False):
                        try:
                            if guessable_element == 'button' and element.getText():
                                button_text = element.getText() #获得内嵌的文字，比如说<a>登录</a>
                                if element.getText() == button_text.strip():#strip()移除首位的空格 
                                    locator = xpath_obj.guess_xpath_button(guessable_element,"text()",element.getText())
                                else:
                                    locator = xpath_obj.guess_xpath_using_contains(guessable_element,"text()",button_text.strip())                                                               
                                if len(self.driver.find_elements_by_xpath(locator))==1:
                                    result_flag = True
                                    self.button_xpaths["%s_%d"%(guessable_element,self.button_index)] = "%s"%(locator.encode('utf-8').decode('latin-1'))
                                    self.button_index+=1
                            else:
                                # if the variable name is already taken
                                print (locator.encode('utf-8').decode('latin-1') + "----> guessable_element != 'button' or element.getText() is None")                       
                        except(InvalidSelectorException):
                              pass  
                else:
                    print("We are not supporting this gussable element")  
        for s in soup(['button','input']):
            s.extract()
        for child in soup.body.descendants:
            if isinstance(child,bs4.element.Tag):
                if(child.has_attr('onclick')):
                    self.guess_xpath_other(child)
        xpaths = [self.input_xpaths, self.button_xpaths]
        return  xpaths
    
    def guess_xpath_other(self,element):
        flag=False
        for attr in self.known_attribute_list:
            if element.has_attr(attr):#这里对一些常见属性进行判断
                locator = self.guess_xpath(element.name,attr,element)
                try:
                    if len(self.driver.find_elements_by_xpath(locator))==1:
                        flag = True
                        self.button_xpaths["%s_%d"%(element.name, self.button_index)] = "%s"%(locator.encode('utf-8').decode('latin-1'))
                        self.button_index+=1
                        break       
                except(InvalidSelectorException):
                    pass  
        if(flag==False):
            try:
                if element.getText():
                    tag_text = element.getText() #获得内嵌的文字，比如说<a>登录</a>
                    if element.getText() == tag_text.strip():#strip()移除首位的空格 
                        locator = xpath_obj.guess_xpath_button(element.name,"text()",element.getText())
                    else:
                        locator = xpath_obj.guess_xpath_using_contains(element.name,"text()",tag_text.strip())                                                               
                    if len(self.driver.find_elements_by_xpath(locator))==1:
                        flag = True
                        self.button_xpaths["%s_%d"%(guessable_element,self.button_index)] = "%s"%(locator.encode('utf-8').decode('latin-1'))
                        self.button_index+=1
                else:
                    # if the variable name is already taken
                    print (locator.encode('utf-8').decode('latin-1') + "----> element doesn't have text!")                  
            except(InvalidSelectorException):
                    pass  
        

    # 基于tag,属性来猜测xpath
    def guess_xpath(self,tag,attr,element):
        "Guess the xpath based on the tag,attr,element[attr]"
        #Class attribute returned as a unicodeded list, so removing 'u from the list and joining back
        if type(element[attr]) is list:
            element[attr] = [i.encode('utf-8').decode('latin-1') for i in element[attr]]
            element[attr] = ' '.join(element[attr])
        self.xpath = "//%s[@%s='%s']"%(tag,attr,element[attr])
 
        return  self.xpath
 
    # 基于tag,不常见属性来猜测button的xpath
    def guess_xpath_button(self,tag,attr,element):
        "Guess the xpath for button tag"
        self.button_xpath = "//%s[%s='%s']"%(tag,attr,element)
 
        return  self.button_xpath
    # 基于tag,包含信息来猜测button的xpath
    def guess_xpath_using_contains(self,tag,attr,element):
        "Guess the xpath using contains function"
        self.button_contains_xpath = "//%s[contains(%s,'%s')]"%(tag,attr,element)
 
        return self.button_contains_xpath
 
 
#-------START OF SCRIPT--------
if __name__ == "__main__":
    print ("Start of %s"%__file__)
 
    #Initialize the xpath object
    
 
    #Get the URL and parse
    # url = input("Enter URL: ")
    url = 'file:///home/summer/Documents/0414/test.html'
 
    #Create a chrome session
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    prefs = { "profile.managed_default_content_settings.images": 2 }
    chrome_options.add_experimental_option("prefs", prefs)

    driver = webdriver.Chrome(executable_path='/usr/bin/chromedriver', chrome_options=chrome_options)

    driver.get(url)
    xpath_obj = Xpath_Util(driver)
    #Parsing the HTML page with BeautifulSoup
    #page = driver.execute_script("return document.body.innerHTML").encode('utf-8').decode('latin-1')#returns the inner HTML as a string return document.documentElement.outerHTML
    page = driver.execute_script("return document.documentElement.outerHTML").encode('utf-8').decode('latin-1')
    soup = BeautifulSoup(page, 'html.parser')
    #execute generate_xpath
    if xpath_obj.generate_xpath(soup) is False:
        print ("No XPaths generated for the URL:%s"%url)
 
    driver.quit()
