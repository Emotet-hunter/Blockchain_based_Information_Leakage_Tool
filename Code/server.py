# -*- coding: utf-8 -*-
"""
Created on Wed May  5 17:04:24 2021

"""

import blockcypher as bcy
import websocket
import json
import requests
import utils
from Crypto.Cipher import AES
import logging

import bech32


LOGGER = logging.getLogger(__name__)
LOGGER.propagate = False
LOGGER.setLevel(logging.DEBUG)
if not LOGGER.handlers:    
    LOGGER.addHandler(logging.StreamHandler())

                    
BCY_API_TOKEN = "5e166bc28a2a4deaaba242594540b344"

INPUT_ADDR = "C1ZDga3zv2xbq7zdiQSLN9GWbDDSGxjbuv"

NAME_WALLET_INPUT = "Mario"


######
#
# @func: Once all the chunks have been received this function decrypts the content
#
#
######

transaction_buffer = {}
record = False
def decrypt_information():
    
    LOGGER.info("Decrypting information...")
    global transaction_buffer, record
    
    cmsg = b""
    
    addr_list = bcy.get_wallet_addresses(wallet_name=NAME_WALLET_INPUT, api_key=BCY_API_TOKEN,coin_symbol="bcy")
    for addr in addr_list["addresses"]:
        if addr in transaction_buffer:
            LOGGER.debug("Retrieved address: " + addr)
            encoded_chunk = transaction_buffer[addr]
            _ , chunk = bech32.decode(hrp="bcy",addr=encoded_chunk)
            cmsg += bytes(chunk)
            LOGGER.debug(bytes(chunk))
    
    pastes = utils.obtain_user_key()
    pastes = utils.read_pastebin()
    
    url = pastes.find_all("paste")[-1].paste_url.string
    LOGGER.debug("Pastebin:" + url)
    sufix = url.split("/")[-1]
    url = utils.PASTEBIN_RAW + "/" + sufix
    
    r = requests.get(url)
    if r.status_code == 200:
        passwd = utils.generate_password(r.text.encode(encoding="ascii",errors="replace"))
        key = passwd[:32]
        iv = passwd[32:48]
        LOGGER.debug(key)
        LOGGER.debug(iv)
        cipher = AES.new(key, AES.MODE_CBC,iv)
        try:
            msg = cipher.decrypt(cmsg)
        except:
            LOGGER.error("Unable to decrypt the message")
            return
        
        
        LOGGER.info(("Message Received: {0}".format(msg.decode())))
        
    else:
        LOGGER.error("Error retrieving the pastebin passphrase")
        return
        
    transaction_buffer = {}
    record = False
    for addr in addr_list["addresses"][1:]:
        LOGGER.debug("Removing address: " + addr)
        bcy.remove_address_from_wallet(NAME_WALLET_INPUT,address = addr,api_key=BCY_API_TOKEN, coin_symbol="bcy")


######
#
# @func: Handler function to process incoming messages from the websocket
#
# @param: Websocket object
#
# @param: Message recieved
#
###### 
 
def on_message(ws, message):
    
    finished = False
    
    LOGGER.info("NEW BLOCK RECIEVED")

    global record, transactions_buffer
        
    block = json.loads(message)
    tx_url = block["tx_url"]
    try:
        for t in block["txids"][1:]:
            r = requests.get(tx_url + t)
            if r.status_code == 200:
                tx = json.loads(r.text)
                address = tx["inputs"][0]["addresses"][0]
                if address == INPUT_ADDR:
                    if record == False:
                        LOGGER.debug("Starting Address Detected")
                        record = True
                    else:
                        finished = True
                        break
                if record:
                    LOGGER.debug("Storing address: "  + address)
                    transaction_buffer[address] = tx["outputs"][0]["addresses"][0]
                        
    except:
        LOGGER.error("Block only has coinbase transaction. Ignoring")
        
    if finished:
       decrypt_information()

######
#
# @func: Handler function to process an error in the websocket communication
#
# @param: Websocket object
#
# @param: Error generated
#
###### 

def on_error(ws, error):
    LOGGER.error(error)

######
#
# @func: Handler function to process the close event in the websocket communication
#
# @param: Websocket object
#
######

def on_close(ws):
    LOGGER.info("### closed ###")

######
#
# @func: Handler function to process the open event in the websocket communication.
#        It is used to send the subscription to the event of new-block
#
# @param: Websocket object
#
######

def on_open(ws):
    ws.send('{ "event": "new-block" }')



######
#
# @func: Creates the socket and establishes a long-lived connection with it
#
#
######

ws = None
def create_websocket():
    websocket.enableTrace(False)
    ws = websocket.WebSocketApp("wss://socket.blockcypher.com/v1/bcy/test?token={0}".format(BCY_API_TOKEN),
                                on_open = on_open,
                                on_message = on_message,
                                on_error = on_error,
                                on_close = on_close)
    
    ws.run_forever(ping_interval=20)

create_websocket()

    
    