# -*- coding: utf-8 -*-
"""
Created on Sat May  8 17:26:46 2021

"""

from bs4 import BeautifulSoup
import requests
import collections
import time
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import logging

LOGGER = logging.getLogger(__name__)
LOGGER.propagate = False
LOGGER.setLevel(logging.DEBUG)
if not LOGGER.handlers:    
    LOGGER.addHandler(logging.StreamHandler())

PASTEBIN_DEV_TOKEN = "-6o1v1F0_Gavw6HPWhDt_kNzuwpfjDGn"
PASTEBIN_USR_TOKEN = ""
PASTEBIN_ARCHIVE = "https://pastebin.com/archive"
PASTEBIN_RAW =  "https://pastebin.com/raw"
PASTEBIN_LOGIN = "https://pastebin.com/api/api_login.php"
PASTEBIN_POST = "https://pastebin.com/api/api_post.php"

MAX_SIZE = 1000


pastebin_entries = collections.deque(maxlen=MAX_SIZE)

######
#
# @func: Poll the pastebin website in order to obtain entries
#        these are stored on a circular buffer
#
#
######
def gather_pb_entries():
    while(True):
        r = requests.get(PASTEBIN_ARCHIVE)
        soup = BeautifulSoup(r.text,'html.parser')
        tr = soup.find_all("tr")
        
        data = ""
        for i in tr[1:]:
            
            c = i.contents
            
            data += c[1].contents[1]["href"] # Entry Raw address
            data += ","
            data += c[1].contents[1].string  # Entry title
            data += ","
            data += c[5].contents[0]["href"].split("/")[2] # Entry syntax
            
            pastebin_entries.append(data)
            data=""
        break
        time.sleep(300)
        

######
#
# @func: Obtain the user api key of pastebin, which enables to create
#        entries thrugh the API is if the user was authenticated
#        in a browser, hence making the entry identifiable by the server 
#
#
######
def obtain_user_key():
    global PASTEBIN_USR_TOKEN
    payload = {"api_dev_key":PASTEBIN_DEV_TOKEN,"api_user_name":"Mapaga",
               "api_user_password":"asdfmovies24"}
    r = requests.post(PASTEBIN_LOGIN, data = payload)
    if r.status_code == 200:
        PASTEBIN_USR_TOKEN = r.text
                    
#######
#
# @func: Post an entry into pastebin
#
# @param: Text to publish
# @param: Title of the paste
# @param: The syntax of the paste
#
######
        
def publish_pastebin(text, title, syntax):

    payload = {"api_dev_key":PASTEBIN_DEV_TOKEN,"api_option":"paste",
               "api_paste_code":text,"api_user_key":PASTEBIN_USR_TOKEN,
               "api_paste_name":title, "api_paste_format":syntax,
               "api_paste_private":"0","api_paste_expire_date":"1H"}
    r = requests.post(PASTEBIN_POST, data = payload)
    
    if r.status_code == 200:
        LOGGER.debug("Publish request response correct")
        return 0
    else: 
        LOGGER.debug("Error publishing the paste")
        return -1
    
    
#######
#
# @func: Read posts of the user
#
#
######
        
def read_pastebin():

    payload = {"api_dev_key":PASTEBIN_DEV_TOKEN,"api_option":"list",
               "api_user_key":PASTEBIN_USR_TOKEN}
    r = requests.post(PASTEBIN_POST, data = payload)
    
    if r.status_code == 200:
        res = "{0}{1}{2}".format("<root>",r.text,"</root>")
        return BeautifulSoup(res,"xml")
    else: return None


######
#
# @func: Create a password for encripting infromation on BCY testnet
#
# @param Pastebin entry used as passphrase
#
######

def generate_password(passphrase):
    salt = b'O\x82Fq\xeegi\x9d\xf6\xc9\x12\xf59d\xc9*'
    key = PBKDF2(passphrase, salt, 64, count=1000000, hmac_hash_module=SHA512)
    return key