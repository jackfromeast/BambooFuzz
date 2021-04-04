from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException,InvalidSelectorException
from bs4 import BeautifulSoup
import re
 
class Xpath_Util:
    "Class to generate the xpaths"
 
    def __init__(self, driver):
        "Initialize the required variables"
        self.driver = driver
        self.elements = None
        self.guessable_elements = ['input','button']
        self.known_attribute_list = ['id','name','placeholder','value','title','type','class']
        self.variable_names = []
        self.button_text_lists = []
        self.input_xpaths = {}
        self.button_xpaths = {}
        self.xpaths = [self.input_xpaths, self.button_xpaths]
        self.language_counter = 1
 
    def generate_xpath(self,soup):
        "generate the xpath and assign the variable names"
        result_flag = False
        for guessable_element in self.guessable_elements:
            self.elements = soup.find_all(guessable_element)
            for element in self.elements:
                if (not element.has_attr("type")) or (element.has_attr("type") and element['type'] != "hidden"):
                    for attr in self.known_attribute_list:
                        if element.has_attr(attr):
                            locator = self.guess_xpath(guessable_element,attr,element)
                            try:
                                if len(self.driver.find_elements_by_xpath(locator))==1:
                                    result_flag = True
                                    variable_name = self.get_variable_names(element)
                                    # checking for the unique variable names
                                    if  variable_name != '' and variable_name not in self.variable_names:
                                        self.variable_names.append(variable_name)
                                        # print ("%s_%s = %s"%(guessable_element, variable_name.encode('utf-8').decode('latin-1'), locator.encode('utf-8').decode('latin-1')))
                                        if element['type'] == 'button':
                                            self.button_xpaths["%s_%s"%(guessable_element, variable_name.encode('utf-8').decode('latin-1'))] = "%s"%(locator.encode('utf-8').decode('latin-1'))
                                        else:
                                            self.input_xpaths["%s_%s"%(guessable_element, variable_name.encode('utf-8').decode('latin-1'))] = "%s"%(locator.encode('utf-8').decode('latin-1'))
                                        break
                                    else:
                                        print (locator.encode('utf-8').decode('latin-1') + "----> Couldn't generate appropriate variable name for this xpath")
                            except(InvalidSelectorException):
                                pass

                        elif guessable_element == 'button' and element.getText():
                            button_text = element.getText()
                            if element.getText() == button_text.strip():
                                locator = xpath_obj.guess_xpath_button(guessable_element,"text()",element.getText())
                            else:
                                locator = xpath_obj.guess_xpath_using_contains(guessable_element,"text()",button_text.strip())
                            
                            try:
                                if len(self.driver.find_elements_by_xpath(locator))==1:
                                    result_flag = True
                                    #Check for utf-8 characters in the button_text
                                    matches = re.search(r"[^\x00-\x7F]",button_text)
                                    if button_text.lower() not in self.button_text_lists:
                                        self.button_text_lists.append(button_text.lower())
                                        if not matches:
                                            # Striping and replacing characters before printing the variable name
                                            # print ("%s_%s = %s"%(guessable_element,button_text.strip().strip("!?.").encode('utf-8').decode('latin-1').lower().replace(" + ","_").replace(" & ","_").replace(" ","_"), locator.encode('utf-8').decode('latin-1')))
                                            
                                            self.button_xpaths["%s_%s"%(guessable_element,button_text.strip().strip("!?.").encode('utf-8').decode('latin-1').lower().replace(" + ","_").replace(" & ","_").replace(" ","_"))] = "%s"%(locator.encode('utf-8').decode('latin-1'))
                                
                                        else:
                                            # printing the variable name with utf-8 characters along with language counter
                                            print ("%s_%s_%s = %s"%(guessable_element,"foreign_language",self.language_counter, locator.encode('utf-8').decode('latin-1')) + "---> Foreign language found, please change the variable name appropriately")
                                            self.language_counter +=1
                                    else:
                                        # if the variable name is already taken
                                        print (locator.encode('utf-8').decode('latin-1') + "----> Couldn't generate appropriate variable name for this xpath")
                                    break
                            except(InvalidSelectorException):
                                pass

 
                        elif not guessable_element in self.guessable_elements:
                            print("We are not supporting this gussable element")
        
        xpaths = [self.input_xpaths, self.button_xpaths]

        return  xpaths
 
    def get_variable_names(self,element):
        "generate the variable names for the xpath"
        # condition to check the length of the 'id' attribute and ignore if there are numerics in the 'id' attribute. Also ingnoring id values having "input" and "button" strings.
        if (element.has_attr('id') and len(element['id'])>2) and bool(re.search(r'\d', element['id'])) == False and ("input" not in element['id'].lower() and "button" not in element['id'].lower()):
            self.variable_name = element['id'].strip("_")
        # condition to check if the 'value' attribute exists and not having date and time values in it.
        elif element.has_attr('value') and element['value'] != '' and bool(re.search(r'([\d]{1,}([/-]|\s|[.])?)+(\D+)?([/-]|\s|[.])?[[\d]{1,}',element['value']))== False and bool(re.search(r'\d{1,2}[:]\d{1,2}\s+((am|AM|pm|PM)?)',element['value']))==False:
            # condition to check if the 'type' attribute exists
            # getting the text() value if the 'type' attribute value is in 'radio','submit','checkbox','search'
            # if the text() is not '', getting the getText() value else getting the 'value' attribute
            # for the rest of the type attributes printing the 'type'+'value' attribute values. Doing a check to see if 'value' and 'type' attributes values are matching.
            if (element.has_attr('type')) and (element['type'] in ('radio','submit','checkbox','search')):
                if element.getText() !='':
                    self.variable_name = element['type']+ "_" + element.getText().strip().strip("_.")
                else:
                    self.variable_name = element['type']+ "_" + element['value'].strip("_.")
            else:
                if element['type'].lower() == element['value'].lower():
                    self.variable_name = element['value'].strip("_.")
                else:
                    self.variable_name = element['type']+ "_" + element['value'].strip("_.")
        # condition to check if the "name" attribute exists and if the length of "name" attribute is more than 2 printing variable name
        elif element.has_attr('name') and len(element['name'])>2:
            self.variable_name = element['name'].strip("_")
        # condition to check if the "placeholder" attribute exists and is not having any numerics in it.
        elif element.has_attr('placeholder') and bool(re.search(r'\d', element['placeholder'])) == False:
            self.variable_name = element['placeholder']
        # condition to check if the "type" attribute exists and not in text','radio','button','checkbox','search'
        # and printing the variable name
        elif (element.has_attr('type')) and (element['type'] not in ('text','button','radio','checkbox','search')):
            self.variable_name = element['type']
        # condition to check if the "title" attribute exists
        elif element.has_attr('title'):
            self.variable_name = element['title']
        # condition to check if the "role" attribute exists
        elif element.has_attr('role') and element['role']!="button":
            self.variable_name = element['role']
        else:
            self.variable_name = ''
 
        return self.variable_name.lower().replace("+/- ","").replace("| ","").replace(" / ","_").  \
        replace("/","_").replace(" - ","_").replace(" ","_").replace("&","").replace("-","_").      \
        replace("[","_").replace("]","").replace(",","").replace("__","_").replace(".com","").strip("_")
 
 
 
    def guess_xpath(self,tag,attr,element):
        "Guess the xpath based on the tag,attr,element[attr]"
        #Class attribute returned as a unicodeded list, so removing 'u from the list and joining back
        if type(element[attr]) is list:
            element[attr] = [i.encode('utf-8').decode('latin-1') for i in element[attr]]
            element[attr] = ' '.join(element[attr])
        self.xpath = "//%s[@%s='%s']"%(tag,attr,element[attr])
 
        return  self.xpath
 
 
    def guess_xpath_button(self,tag,attr,element):
        "Guess the xpath for button tag"
        self.button_xpath = "//%s[%s='%s']"%(tag,attr,element)
 
        return  self.button_xpath
 
    def guess_xpath_using_contains(self,tag,attr,element):
        "Guess the xpath using contains function"
        self.button_contains_xpath = "//%s[contains(%s,'%s')]"%(tag,attr,element)
 
        return self.button_contains_xpath
 
 
#-------START OF SCRIPT--------
if __name__ == "__main__":
    print ("Start of %s"%__file__)
 
    #Initialize the xpath object
    xpath_obj = Xpath_Util()
 
    #Get the URL and parse
    # url = input("Enter URL: ")
    url = 'http://192.168.10.1'
 
    #Create a chrome session
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    prefs = { "profile.managed_default_content_settings.images": 2 }
    chrome_options.add_experimental_option("prefs", prefs)

    driver = webdriver.Chrome(executable_path='/usr/bin/chromedriver', chrome_options=chrome_options)

    driver.get(url)
 
    #Parsing the HTML page with BeautifulSoup
    page = driver.execute_script("return document.body.innerHTML").\
    encode('utf-8').decode('latin-1')#returns the inner HTML as a string
    soup = BeautifulSoup(page, 'html.parser')
 
    #execute generate_xpath
    if xpath_obj.generate_xpath(soup) is False:
        print ("No XPaths generated for the URL:%s"%url)
 
    driver.quit()