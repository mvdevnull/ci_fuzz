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
                ./dev.sh    #If error missing python.h headers - try apt-get install python3-dev
		
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
