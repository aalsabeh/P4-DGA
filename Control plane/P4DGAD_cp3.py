from os import uname
from crccheck.crc import Crc32, CrcXmodem, Crc16Genibus
from crccheck.checksum import Checksum32
import numpy as np
import bitarray
import socket
import struct
import binascii
from bitstring import BitArray
import struct
import csv
import math
import socket
import threading
import time
import RF



RR_A = 1
RR_CNAME = 5
LABEL_LENGTH = 7
LABEL_LENGTH_BITS = LABEL_LENGTH * 8
RF_MODEL = None
SC = None
HOSTS_iarrival =  {}

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        #self.sock.listen(5)
        self.sock.listen()

        client, address = self.sock.accept()
        #client.settimeout(60)
        threading.Thread(target = self.listenToClient,args = (client,address)).start()

        # while True:
        #     client, address = self.sock.accept()
        #     client.settimeout(60)
        #     threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        while True:
            try:
                data = client.recv(size)
                if data:
                    # Set the response to echo back the recieved data 
                    response = data.decode()
                    # convert response to IP
                    print(socket.inet_ntoa(struct.pack('!L', int(response)))) 
                    #client.send(response)
                else:
                    raise error('Client disconnected')
            except:
                print("Connection terminated")
                client.close()
                return False




'''
###################### old_server
def create_server():   
    host = socket.gethostname()
    port = 12397
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("Listening")
        conn, addr = s.accept()
        with conn:
            while not conn == None :
                data = conn.recv(1024).decode()
                if not data:
                    break
                print(data)
                #break
#create_server()
'''

#"""
def load_bigram_scores(csv_file_name):
    '''
    Takes as csv_file the bigram scores file, typically it is "bigram_scores_P4_8.csv"
    Returns: dictionary key = hexadecimal of the bigram, value = frequency
    '''
    bigram_freq = {}
    with open(csv_file_name) as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        i = 0
        for row in csv_reader:
            i += 1
            bigram_freq[row[1]] = math.floor(float(row[2]))
    
        return bigram_freq


bigram_freq = load_bigram_scores("bigram_scores_engDic.csv")  
# bigram_freq = load_bigram_scores("p4_freq_rules_gen.csv")

def fill_P4_labels(label):
    part1 = ""
    part2 = ""
    part4 = ""
    
    if len(label) > 7:
        label = label[:7]
        
    if len(label) == 1:
        part1 = label
    elif len(label) == 2:
        part2 = label
    elif len(label) == 3:
        part1 = label[:1]
        part2 = label[1:]
    elif len(label) == 4:
        part4 = label
    elif len(label) == 5:
        part1 = label[:1]
        part4 = label[1:]
    elif len(label) == 6:
        part2 = label[:2]
        part4 = label[2:]
    elif len(label) == 7:
        part1 = label[:1]
        part2 = label[1:3]
        part4 = label[3:]
        
    return part1, part2, part4

def bit_div(a,b):
    ''' 
        Divides a by b
    '''
    ans = 0 # the quotient is intialized

    neg = a < 0 or b < 0 # Checking if one of the numbers is negative

    a = abs(a) # making sure both the numbers
    b = abs(b) # are positive

    for i in range(31,-1,-1): # starting our loop
        if b << i <= a  : # checking if b multiplied by 2**i is <= a 
            a -= b << i   # subtracting b << i from a
            ans += 1 << i # adding 2 power i to the answer

    # and finally checking if the output should be negative and returning it
    return ans if neg == 0 else -1 * ans

def get_bigram_freq(bigram_freq_dict, hex_val):
    if hex_val in bigram_freq_dict:
        return bigram_freq_dict[hex_val]
    return 0
      
def calc_P4_score(domain):
    global bigram_freq
    
    domain_ls = domain.split(".")
    if len(domain_ls) <= 1:
        return 0
    score = 0
    total_len = 0
    
    # Don't count 
    for label_index in range(len(domain_ls) -1):
        label = domain_ls[label_index]
        total_len += len(domain_ls[label_index])
        
        while len(label) >= 1:
            q1_part1, q1_part2, q1_part4 = fill_P4_labels(label)
            if q1_part1 != "":
#                 print("q1_part1")
                hex_val = format(ord("c"), "x")
                hex_val = "0x20" + hex_val # 0x20 is a space (first character)
#                 print(hex_val)
                score += get_bigram_freq(bigram_freq, hex_val)
                
            if q1_part2 != "":
#                 print("q1_part2")
                hex_val = "0x" + format(ord(q1_part2[0]), "x") + format(ord(q1_part2[1]), "x")
                score += get_bigram_freq(bigram_freq, hex_val)
#                 print("hex_val = ", hex_val, " score = ", score, "(" + hex(score) + ")")
            
            if q1_part2 != "" and q1_part1 != "":
#                 print("q1_part1 and q1_part2")
                hex_val = "0x" + format(ord(q1_part1[0]), "x") + format(ord(q1_part2[0]), "x")
                score += get_bigram_freq(bigram_freq, hex_val)
#                 print("hex_val = ", hex_val, " score = ", score, "(" + hex(score) + ")")
            
            if q1_part4 != "":
#                 print("q1_part4")
                hex_val = "0x" + format(ord(q1_part4[0]), "x") + format(ord(q1_part4[1]), "x")
                score += get_bigram_freq(bigram_freq, hex_val)
#                 print("hex_val = ", hex_val, " score = ", score, "(" + hex(score) + ")")
                
                hex_val = "0x" + format(ord(q1_part4[1]), "x") + format(ord(q1_part4[2]), "x")
                score += get_bigram_freq(bigram_freq, hex_val)
#                 print("hex_val = ", hex_val, " score = ", score, "(" + hex(score) + ")")
                
                hex_val = "0x" + format(ord(q1_part4[2]), "x") + format(ord(q1_part4[3]), "x")
                score += get_bigram_freq(bigram_freq, hex_val)
#                 print("hex_val = ", hex_val, " score = ", score, "(" + hex(score) + ")")
            
            if q1_part4 != "" and q1_part2 != "":
#                 print("q1_part4 and part2")
                hex_val = "0x" + format(ord(q1_part2[1]), "x") + format(ord(q1_part4[0]), "x")
                score += get_bigram_freq(bigram_freq, hex_val)
#                 print("hex_val = ", hex_val, " score = ", score, "(" + hex(score) + ")")
                
            elif q1_part4 != "" and q1_part1 != "":
#                 print("q1_part4 and part 1")
                hex_val = "0x" + format(ord(q1_part1[0]), "x") + format(ord(q1_part4[0]), "x")
                score += get_bigram_freq(bigram_freq, hex_val)
#                 print("hex_val = ", hex_val, " score = ", score, "(" + hex(score) + ")")
                
            label = label[min(7, len(label)):]
#     return score
    return bit_div(score, total_len)


def hex_to_binary(my_hexdata, num_of_bits):
    scale = 16 ## equals to hexadecimal
    return bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

def str_to_binary(label):
    ba = bitarray.bitarray()
    ba.frombytes(label.encode('utf-8'))
    return ba.tolist()

def bitstring_to_bytes(s):
    '''
    From string of bits to bytearray
    '''
    # python2
    # return struct.pack(int(s, 2), )
    # python3
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')
    

    
def calc_crc_16_IP(ip):
    '''
    Takes IP address (regular IP format 1.1.1.1), casts it to 56-bit (according to the label length)
    Returns the hash in hexadecimal
    '''
    ip_to_bytes = binascii.hexlify(socket.inet_aton(ip))
    ip_to_hex = ip_to_bytes.decode("utf-8")
    c = BitArray(hex=ip_to_hex)
    full_label = "0"*20 + c.bin
    binary = bitstring_to_bytes(full_label)
    crc_genibus = Crc16Genibus()
    crc_genibus.process(binary)
    return crc_genibus.finalhex()


#ip_addr = "192.168.200.10"
#print("HASH OF IP ", ip_addr, calc_crc_16_IP(ip_addr))



def calc_crc_16_P4(url):
    ''' 
    Takes a url and returns the hashes of every label in a list 
    The hashing is based on the P4 program
    '''
    url = url.split(".")
    hashes = []
    try:
        for label in url:
            full_label = np.zeros((LABEL_LENGTH_BITS))
            bit_index = LABEL_LENGTH_BITS
            label_index = 0

            # part 1
            if not len(label)%2 == 0:
                parse_chars = label[label_index]
                full_label[bit_index - 8:bit_index] = str_to_binary(parse_chars)
                label_index += 1 # 1 char parsed
            bit_index -= 8

            # part 2
            if len(label) == 2 or len(label) == 3 or len(label) == 6 or len(label) == 7:
                # parse two characters (16 bits)
                parse_chars = ''.join(label[label_index: label_index + 2])
                full_label[bit_index - 16:bit_index] = str_to_binary(parse_chars)
                label_index += 2 # 2 chars parsed
            bit_index -= 16

            # part 4
            if (len(label) >= 4 and len(label) <= 7):
                # parse 4 characters
                parse_chars = ''.join(label[label_index: label_index + 4])
                full_label[bit_index - 32:bit_index] = str_to_binary(parse_chars)
                label_index += 4 # 4 chars parsed
            bit_index -= 32

            full_label = [str(int(a)) for a in full_label] # from list of float to list of str
            full_label = ''.join(list(full_label)) # concat to string
            binary = bitstring_to_bytes(full_label)
            crc_genibus = Crc16Genibus()
            crc_genibus.process(binary)
            hashes.append(crc_genibus.finalhex())
    except Exception as e:
        print(e)
        return -1
        
    return hashes


#print("hash of abc.efg.acdefgh", calc_crc_16_P4("abc.efg.abcdefgh"))
# print()

def hash_concat_hashes(url, initial_hash_str):
    '''
    Takes:
    url: the domain that needs to be hashed (per label), such as "NS2.AMERICATELNET.COM.PE"
    initial_hash_str: the initial hash in hexademical form (16bit) represented in a string, such as "0000" or "14e5"
    NOTE: THE URL MUST BE 4 LABELS
    
    Returns:
    list: the hash concatenation of the whole URL, aka hash_concat_hashes
    '''
    def binarystring_to_binarylist(word):
        binary_list = []
        for b in word:
            if b == '0':
                binary_list.append(False)
            else:
                binary_list.append(True)
                
        return binary_list
    
    hashes = calc_crc_16_P4(url)
    # loop over all the labels
    for label in url.split("."):
        # loop over every 7 characters of the label
        flag = 0
        while flag == 0:
            full_label = np.zeros((32))
            if len(label) <= 7:
                hashes = calc_crc_16_P4(label)
                flag = 1
            else:
                hashes = calc_crc_16_P4(label[:7])
                label = label[7:]
            
            aa = [a for a in hex_to_binary(initial_hash_str, 16)]
            full_label[0:16] = aa
            aa = [a for a in hex_to_binary(hashes[0], 16)]
            full_label[16:32] = aa

            full_label = [str(int(a)) for a in full_label]
            full_label = ''.join(list(full_label))
            binary = bitstring_to_bytes(full_label)
            crc_genibus = Crc16Genibus()
            crc_genibus.process(binary)

            initial_hash_str = crc_genibus.finalhex()

    return initial_hash_str


#print("Hash concat Hashes", hash_concat_hashes("abc.googleee.doodleee", "0000"))

def hash_last_label(last_label_str):
    '''
    Takes:
    url: the domain that needs to be hashed (per label), such as "NS2.AMERICATELNET.COM.PE"
    initial_hash_str: the initial hash in hexademical form (16bit) represented in a string, such as "0000" or "14e5"
    NOTE: THE URL MUST BE 4 LABELS
    
    Returns:
    list: the hash concatenation of the whole URL, aka hash_concat_hashes
    '''
    initial_hash_str = "0000"
    
    while True:
        full_label = np.zeros((32))
        if len(last_label_str) == 0:
            break
        elif len(last_label_str) <= LABEL_LENGTH:
            hashes = calc_crc_16_P4(last_label_str)
        else:
            hashes = calc_crc_16_P4(last_label_str[:LABEL_LENGTH])

        if hashes != -1:
            aa = [a for a in hex_to_binary(initial_hash_str, 16)]
            full_label[0:16] = aa
            aa = [a for a in hex_to_binary(hashes[0], 16)]
            full_label[16:32] = aa

            full_label = [str(int(a)) for a in full_label]
            full_label = ''.join(list(full_label))
            binary = bitstring_to_bytes(full_label)
            crc_genibus = Crc16Genibus()
            crc_genibus.process(binary)

            initial_hash_str = crc_genibus.finalhex()
            
            last_label_str = last_label_str[min(LABEL_LENGTH, len(last_label_str)):]

        else:
            return "-1"

    return initial_hash_str


class ThreadedServer(object):
    global RF_MODEL
    global SC
    global HOSTS_iarrival

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        #self.sock.listen(5)
        self.sock.listen()

        client, address = self.sock.accept()
        #client.settimeout(60)
        threading.Thread(target = self.listenToClient,args = (client,address)).start()

        # while True:
        #     client, address = self.sock.accept()
        #     #client.settimeout(60)
        #     threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        while True:
            try:
                data = client.recv(size)
                if data:
                    # Set the response to echo back the recieved data 
                    response = data.decode()
                    # convert response to IP
                    print(response)
                    response = response.split(",")
                    ip_addr = response[0]
                    ip_addr= socket.inet_ntoa(struct.pack('!L', int(ip_addr)))
                    non_rnd_nxds = int(response[1])
                    rnd_nxds = int(response[2])
                    nb_nxds = rnd_nxds + non_rnd_nxds
                    nb_unique_ips = int(response[3])
                    nb_dns_reqs = int(response[4])

                    if ip_addr in HOSTS_iarrival:
                        HOSTS_iarrival[ip_addr].append(time.time())
                    else:
                        HOSTS_iarrival[ip_addr] = [time.time()]
                        
                    print("IP address %s\t (%s, %s, %s, %s)" %(ip_addr, nb_nxds, rnd_nxds, nb_unique_ips, nb_dns_reqs))
                    #client.send(response)

                    # run the classifer
                    X_curr = ([[int(nb_dns_reqs)//(int(nb_unique_ips)+1), rnd_nxds, nb_nxds,  sum(HOSTS_iarrival[ip_addr])//len(HOSTS_iarrival[ip_addr]) ]])
                    print("Data = ", X_curr)
                    print("Data standard scaled = ", SC.transform(X_curr))
                    # query the register values from the data plane
                    #  
                else:
                    raise error('Client disconnected')
            except Exception as e:
                print(e)
                print("Connection terminated")
                client.close()
                #ThreadedServer('',self.port).listen()
                return False



if __name__ == "__main__":
    host = socket.gethostname()
    port_num = 12397

    # Train model
    RF_MODEL, SC = RF.train_RF_model(event = 4)
    print("Listening to server")
    ThreadedServer('',port_num).listen()



# print("Hash_last_label", hash_last_label("googleee"))

# abc
# print("a".encode('utf-8').hex())
# print("bc".encode('utf-8').hex())
# print("ab".encode('utf-8').hex())

# googleee
# print("g".encode('utf-8').hex())
# print("go".encode('utf-8').hex())
# print("oo".encode('utf-8').hex())
# print("og".encode('utf-8').hex())
# print("gl".encode('utf-8').hex())
# print("le".encode('utf-8').hex())

# e
#print("e".encode('utf-8').hex())
#"""
