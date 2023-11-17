import os
from re import sub
import time
from ipaddress import ip_address
import socket


#"""
p4 = bfrt.DGA.pipe



# clear table rules
def clear_tables():
    print("Clearing table ...")
    p4.SwitchEgress.static_bigram_p1p2.clear()
    p4.SwitchEgress.static_bigram_p1p4.clear()
    p4.SwitchEgress.static_bigram_p2.clear()
    p4.SwitchEgress.static_bigram_p2p4.clear()
    p4.SwitchEgress.static_bigram_p4_1.clear()
    p4.SwitchEgress.static_bigram_p4_2.clear()
    p4.SwitchEgress.static_bigram_p4_3.clear()
    # p4.SwitchEgress.static_ngram8_1.clear()
    # p4.SwitchEgress.static_ngram8_2.clear()
    # p4.SwitchEgress.static_ngram8_3.clear()
    # p4.SwitchEgress.static_ngram8_4.clear()
    # p4.SwitchEgress.static_ngram8_5.clear()
    # p4.SwitchEgress.static_ngram8_6.clear()
    # p4.SwitchEgress.static_ngram9.clear()

    p4.SwitchIngress.ipv4_host.clear()


clear_tables()

def load_tables():
    print("Loading the tables ...")
    table_entries_dir = "./tables_entries"
    for file in os.listdir(table_entries_dir):
        filename = os.fsdecode(file)

        # if filename != "static_ngram4_1.txt" and filename != "static_ngram4_2.txt" and filename != "static_ngram3.txt":
        #     continue

        abs_path = os.path.join(table_entries_dir, filename)
        print(abs_path)
        with open(abs_path) as fr:
            for l in fr:
                exec(l.strip()) 

    print("DONE INSERTING FREQUENCIES")

load_tables()

# For basic forwarding and testing
def forward_testing():
    p4.SwitchIngress.ipv4_host.add_with_send(dst="192.168.200.10", port=0)
    p4.SwitchIngress.ipv4_host.add_with_send(dst="192.168.200.11", port=1)
    # p4.SwitchIngress.static_bigrams1.add_with_map_bigram_hdr(part=)

forward_testing()

#"""

def is_valid_tld():
    # Table to check for valid TLDs
    f_r = open("./tlds_to_P4hex.txt")
    tld_P4hex = []
    for l in f_r:
        l = l.strip()
        l = l.split(",")
        tld_hash = "0x" + l[1]
        if tld_hash not in tld_P4hex:
            tld_P4hex.append(tld_hash)
            p4.SwitchIngress.is_valid_tld.add_with_is_valid_tld_act(hash_last_label=tld_hash)

# is_valid_tld()

def establish_connection():
    import socket
    import time

    s = socket.socket()
    host = socket.gethostname()
    port = 12397
    #s.bind(('', port))
    s.connect((host, port))

    return s

# establish connection
# s = establish_connection()

# IP to P4 hex dict:
ip_to_p4hex = {'3232286730': '0x971f', '3232286731': '0x873e', '3232286732': '0xf7d9'}

def create_client(s):
    import socket
    import time

    s = socket.socket()
    host = socket.gethostname()
    port = 12397
    s.connect((host, port))
    while True:
        s.send("Hello World".encode())
        time.sleep(5)
        break

    s.close()

def digest_event(dev_id, pipe_id, direction, parser_id, session, msg):
    global p4 # bfrt.P4DGAD.pipe
    global s # socket
    global ip_to_p4hex

    try:
        for digest in msg:
            dga_ip = digest['dga_ip']
            ip_reqs = digest['ip_reqs']
            dns_reqs = digest['dns_reqs']
            bigram = digest['bigram']
            domain_name_length = digest["domain_name_length"];
            num_subdomains = digest["num_subdomains"];
            tld_hash = digest["hash_last_label"]
            
            
            print("Incoming packet with DGA IP: ", dga_ip, "\n"
                  "#IP reqs: ", ip_reqs, "\n",
                  "#DNS reqs: ", dns_reqs, "\n",
                  "#bigram val: ", bigram, "\n",
                  "#domain_name_length: ", domain_name_length, "\n",
                  "#num_subdomains: ", num_subdomains, "\n",
                  "#tld_hash: ", tld_hash, "\n",)

            '''
            Since we are using python2 as the control plane for the current SDE, advanced ML models and libraries are not available.
            If you would like to test your data on ML models using python3, you can open a socket with python3 code to send the data and run them there. 
            Below is the code to send the data to python3 code, feel free to uncomment it and play with it.
            Also, the python3 server code is in P4DGAD_cp3.py. 
            send the data collected to python3 where you can ML models using scikit learn and other advanced tools 
            ''' 
            # data = ip_addr + "," + nb_nxds + "," + rnd_nxds + ',' + nb_unique_ips + ',' + nb_dns_reqs
            # print(data.encode())
            # s.send(data.encode())
    except Exception as e:
        print(e)

    return 0

try:
    p4.SwitchIngressDeparser.digest.callback_register(digest_event)
except:
    # deregister then register again
    p4.SwitchIngressDeparser.digest.callback_deregister()
    p4.SwitchIngressDeparser.digest.callback_register(digest_event)


