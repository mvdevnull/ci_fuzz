'''
Run this script in a separate console to identify ping data from ci_fuzz.py - the serial number will match the payload

Usage:
python3 ./icmp.py
'''

'''
BUGS/TODO   getting this error on some packets  TypeError: ord() expected string of length 1, but int found
'''

import socket
import binascii

print("Listening for ci_fuzz.py command execution pings ....")
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.bind(('', 0))
contents = ""

try :
  while True :
    #Looking for icmp similiar to result of ping -s 14 -c 1 -p 020000000000000000000000000001 192.168.86.37 (size 14)
    data = sock.recv(43) #RFC says ICMP should <= 65507 = (65535 - 20 - 8).  fuzzer's size will be <=42 = (14+20+8)
    try:
        data_str = [ord(c) for c in data]
        #print("DEBUG:Entire ICMP packet (ord)->%s" % data_str)
        if len(data) == 42:
    	    ip_header = data[:20]  #ip header supposed to be first 20 bytes
    	    data_spot = len(data)-28
    	    contents = data[-data_spot:]
    	    contents_str = [ord(c) for c in contents]
    	    ips = ip_header[-8:-4]
    	    source = '%i.%i.%i.%i' % (ord(ips[0]), ord(ips[1]), ord(ips[2]), ord(ips[3]))
    	    print("CI_FUZZ execution!!!! Ping from %s - serial number ->%s" % (source, binascii.b2a_hex(contents)))
        else:
            print("DEBUG - not a CI_FUZZ packet - wrong size!!")
    except TypeError:
        #print("DEBUG- skipping wierd icmp")
        pass
except KeyboardInterrupt :
    print("Closing ")

